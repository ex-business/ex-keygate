package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"ex-keygate/internal/access"
	"time"
)

type AuditFilter struct {
	Action    string    `json:"action"`
	Result    string    `json:"result"`
	RequestID string    `json:"requestId"`
	TargetID  string    `json:"targetId"`
	ClientID  string    `json:"clientId"`
	After     int64     `json:"after,string"`
	Limit     int       `json:"limit"`
	From      time.Time `json:"from"`
	Until     time.Time `json:"until"`
}
type AuditEvent struct {
	Sequence    int64     `json:"sequence,string"`
	EventID     string    `json:"eventId"`
	Environment string    `json:"environment"`
	ClientID    string    `json:"clientId"`
	RequestID   string    `json:"requestId"`
	ActorID     string    `json:"actorId"`
	Action      string    `json:"action"`
	TargetID    string    `json:"targetId"`
	Result      string    `json:"result"`
	RecordedAt  time.Time `json:"recordedAt"`
}

func validAuditFilter(f AuditFilter, max int) bool {
	for _, id := range []string{f.Action, f.Result, f.RequestID, f.TargetID} {
		if id != "" && !access.ValidID(id) {
			return false
		}
	}
	return (f.ClientID == "" || access.ValidID(f.ClientID)) && f.After >= 0 && f.Limit > 0 && f.Limit <= max && !f.From.IsZero() && f.Until.After(f.From) && f.Until.Sub(f.From) <= 31*24*time.Hour
}

// auditRows 仅选择白名单审计字段，既不联接秘密列，也不把未验证客户端声明当作可信身份。
func (c *DevelopmentControl) auditRows(ctx context.Context, tx *sql.Tx, actor string, f AuditFilter) ([]AuditEvent, error) {
	if !c.has(ctx, tx, actor, access.Auditor, f.ClientID) {
		return nil, ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT a.sequence,a.event_id,s.environment,s.client_id,a.request_id,a.actor_id,a.action,a.target_id,a.result,a.created_at FROM keygate.audit_events a JOIN keygate.scoped_audit s ON s.event_id=a.event_id WHERE s.environment=$1 AND ($2='' OR s.client_id=$2) AND a.sequence>$3 AND a.created_at>=$4 AND a.created_at<$5 AND ($7='' OR a.action=$7) AND ($8='' OR a.result=$8) AND ($9='' OR a.request_id=$9) AND ($10='' OR a.target_id=$10) ORDER BY a.sequence LIMIT $6`, c.environment, f.ClientID, f.After, f.From, f.Until, f.Limit, f.Action, f.Result, f.RequestID, f.TargetID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var a AuditEvent
		if e = rows.Scan(&a.Sequence, &a.EventID, &a.Environment, &a.ClientID, &a.RequestID, &a.ActorID, &a.Action, &a.TargetID, &a.Result, &a.RecordedAt); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (c *DevelopmentControl) AuditQuery(ctx context.Context, token string, f AuditFilter) ([]AuditEvent, error) {
	if !validAuditFilter(f, 100) {
		return nil, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	out, e := c.auditRows(ctx, tx, a.id, f)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}

type AuditExport struct {
	Filter               AuditFilter
	ID, State, Digest    string
	Count                int
	CreatedAt, ExpiresAt time.Time
}

// ExportAudit 将同一事务快照的白名单行物化为 JSONL；不拼接普通分页，不提供可执行 CSV。
func (c *DevelopmentControl) ExportAudit(ctx context.Context, token string, f AuditFilter, trace string) (AuditExport, error) {
	if !validAuditFilter(f, 5000) || !access.ValidID(trace) || f.After != 0 {
		return AuditExport{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return AuditExport{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return AuditExport{}, e
	}
	// 开发配额限制导出积压和敏感元数据驻留；清理过期载荷不删除既有审计事实。
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.audit_exports SET payload=''::bytea WHERE environment=$1 AND expires_at<=clock_timestamp() AND octet_length(payload)>0`, c.environment); e != nil {
		return AuditExport{}, e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.audit_exports WHERE environment=$1 AND expires_at<clock_timestamp()-interval '1 day'`, c.environment); e != nil {
		return AuditExport{}, e
	}
	var total, mine int
	if e = tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE principal_id=$2) FROM keygate.audit_exports WHERE environment=$1 AND expires_at>clock_timestamp()`, c.environment, a.id).Scan(&total, &mine); e != nil {
		return AuditExport{}, e
	}
	if total >= 100 || mine >= 10 {
		return AuditExport{}, ErrConflict
	}
	requestedFilter := f
	f.Limit++
	// 多读一行拒绝截断导出；不能把遗漏事件的局部结果标为完整快照。
	rows, e := c.auditRows(ctx, tx, a.id, f)
	if e != nil {
		return AuditExport{}, e
	}
	if len(rows) >= f.Limit {
		return AuditExport{}, ErrConflict
	}
	var payload bytes.Buffer
	enc := json.NewEncoder(&payload)
	for _, row := range rows {
		if e = enc.Encode(row); e != nil {
			return AuditExport{}, e
		}
	}
	if payload.Len() > 8<<20 {
		return AuditExport{}, ErrInvalid
	}
	id, e := controlID()
	if e != nil {
		return AuditExport{}, e
	}
	out := AuditExport{ID: id, State: "ready", Digest: digestBytes(payload.Bytes()), Count: len(rows), Filter: requestedFilter}
	filters, e := json.Marshal(requestedFilter)
	if e != nil {
		return AuditExport{}, e
	}
	if e = tx.QueryRowContext(ctx, `INSERT INTO keygate.audit_exports(environment,export_id,principal_id,client_id,payload,digest,event_count,filters) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at,expires_at`, c.environment, id, a.id, f.ClientID, payload.Bytes(), out.Digest, out.Count, string(filters)).Scan(&out.CreatedAt, &out.ExpiresAt); e != nil {
		return AuditExport{}, e
	}
	if e = c.audit(ctx, tx, trace, a.id, "audit_export", id, "ready"); e != nil {
		return AuditExport{}, e
	}
	if e = tx.Commit(); e != nil {
		return AuditExport{}, e
	}
	return out, nil
}

// DownloadAudit 每次下载复查所有者、近期认证、当前 auditor 范围和期限；任务 ID 不是授权凭据。
func (c *DevelopmentControl) DownloadAudit(ctx context.Context, token, id, trace string) ([]byte, error) {
	if !access.ValidID(id) || !access.ValidID(trace) {
		return nil, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return nil, e
	}
	var payload []byte
	var scope, digest string
	if e = tx.QueryRowContext(ctx, `SELECT client_id,payload,digest FROM keygate.audit_exports WHERE environment=$1 AND export_id=$2 AND principal_id=$3 AND expires_at>clock_timestamp()`, c.environment, id, a.id).Scan(&scope, &payload, &digest); e != nil {
		return nil, e
	}
	if !c.has(ctx, tx, a.id, access.Auditor, scope) {
		return nil, ErrDenied
	}
	if digestBytes(payload) != digest {
		return nil, ErrConflict
	}
	if e = c.audit(ctx, tx, trace, a.id, "audit_download", id, "success"); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return payload, nil
}
func (c *DevelopmentControl) AuditExports(ctx context.Context, token string) ([]AuditExport, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT x.export_id,x.client_id,x.digest,x.event_count,x.created_at,x.expires_at,x.filters,CASE WHEN x.expires_at>clock_timestamp() THEN 'ready' ELSE 'expired' END FROM keygate.audit_exports x WHERE x.environment=$1 AND x.principal_id=$2 AND EXISTS(SELECT 1 FROM keygate.role_grants g WHERE g.environment=x.environment AND g.principal_id=$2 AND g.role='auditor' AND g.enabled AND (g.client_id='' OR g.client_id=x.client_id)) ORDER BY x.created_at DESC LIMIT 100`, c.environment, a.id)
	if e != nil {
		return nil, e
	}
	out := []AuditExport{}
	for rows.Next() {
		var x AuditExport
		var scope string
		var filters []byte
		if e = rows.Scan(&x.ID, &scope, &x.Digest, &x.Count, &x.CreatedAt, &x.ExpiresAt, &filters, &x.State); e != nil {
			rows.Close()
			return nil, e
		}
		if e = json.Unmarshal(filters, &x.Filter); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}

// RecordAuthFailure 固定原因及分钟聚合，不按攻击者自报客户端建维度，避免敏感信息与高基数放大。
func (c *DevelopmentControl) RecordAuthFailure(ctx context.Context, reason, trace string) error {
	if (reason != "denied" && reason != "unavailable" && reason != "rate_limited") || !access.ValidID(trace) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var attempts int64
	e = tx.QueryRowContext(ctx, `INSERT INTO keygate.auth_failure_buckets(environment,minute,reason,attempts) VALUES($1,date_trunc('minute',clock_timestamp()),$2,1) ON CONFLICT(environment,minute,reason) DO UPDATE SET attempts=LEAST(keygate.auth_failure_buckets.attempts+1,1000000000) RETURNING attempts`, c.environment, reason).Scan(&attempts)
	if e != nil {
		return e
	}
	if attempts == 1 {
		if e = c.audit(ctx, tx, trace, "unverified", "auth_reject", c.environment, reason); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.auth_failure_buckets WHERE environment=$1 AND minute<clock_timestamp()-interval '24 hours'`, c.environment); e != nil {
		return e
	}
	return tx.Commit()
}

type AuthFailure struct {
	Minute   time.Time
	Reason   string
	Attempts int64
}

func (c *DevelopmentControl) AuthFailures(ctx context.Context, token string) ([]AuthFailure, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	if !c.has(ctx, tx, a.id, access.Auditor, "") {
		return nil, ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT minute,reason,attempts FROM keygate.auth_failure_buckets WHERE environment=$1 AND minute>=clock_timestamp()-interval '24 hours' ORDER BY minute DESC,reason LIMIT 4320`, c.environment)
	if e != nil {
		return nil, e
	}
	out := []AuthFailure{}
	for rows.Next() {
		var f AuthFailure
		if e = rows.Scan(&f.Minute, &f.Reason, &f.Attempts); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, f)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}

// auditScope 依据已提交到同事务的真实业务对象关联范围，不信任请求自报 scope。
func (c *DevelopmentControl) auditScope(ctx context.Context, tx *sql.Tx, action, target string) (string, error) {
	var query string
	switch action {
	case "control_submit", "control_vote", "control_execute":
		query = `SELECT convert_from(manifest,'UTF8')::jsonb->'operation'->>'clientId' FROM keygate.control_requests WHERE environment=$1 AND request_id=$2`
	case "key_claim", "key_possession":
		query = `SELECT client_id FROM keygate.key_versions WHERE environment=$1 AND issue_id=$2`
	case "recovery_abort":
		query = `SELECT client_id FROM keygate.recovery_tasks WHERE environment=$1 AND recovery_id=$2`
	case "audit_export", "audit_download":
		query = `SELECT client_id FROM keygate.audit_exports WHERE environment=$1 AND export_id=$2`
	case "application_trust_certificate_download", "application_trust_revoke", "application_trust_status", "client_disable", "client_auth", "browser_session_create", "browser_auth", "browser_logout":
		return target, nil
	case "key_revoke":
		query = `SELECT client_id FROM keygate.revocations WHERE environment=$1 AND incident_id=$2`
	default:
		return "", nil
	}
	var scope string
	if e := tx.QueryRowContext(ctx, query, c.environment, target).Scan(&scope); e != nil {
		return "", e
	}
	if scope == "root-management" || scope == "provider-management" {
		scope = ""
	}
	return scope, nil
}
