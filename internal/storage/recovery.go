package storage

import (
	"context"
	"ex-keygate/internal/access"
	"time"
)

type RecoveryTask struct {
	ID, ClientID, IncidentID, EvidenceHash, IssueID, State string
	Version                                                uint64
	CreatedAt                                              time.Time
	FinishedAt                                             *time.Time
}

// Recoveries 在读取时复查权限；任务和执行日志是响应丢失后的权威核对事实，不重发秘密。
func (c *DevelopmentControl) Recoveries(ctx context.Context, token, client string) ([]RecoveryTask, error) {
	if !access.ValidID(client) {
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
	if !c.has(ctx, tx, a.id, access.Viewer, client) {
		return nil, ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT recovery_id,client_id,incident_id,evidence_hash,issue_id,state,key_version,created_at,finished_at FROM keygate.recovery_tasks WHERE environment=$1 AND client_id=$2 ORDER BY created_at DESC,recovery_id LIMIT 100`, c.environment, client)
	if e != nil {
		return nil, e
	}
	out := []RecoveryTask{}
	for rows.Next() {
		var r RecoveryTask
		if e = rows.Scan(&r.ID, &r.ClientID, &r.IncidentID, &r.EvidenceHash, &r.IssueID, &r.State, &r.Version, &r.CreatedAt, &r.FinishedAt); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, r)
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

// AbortRecovery 只减权并保留原任务；允许新方案重新申请，不会清空原预算、领取或批准事实。
func (c *DevelopmentControl) AbortRecovery(ctx context.Context, token, id, trace string) error {
	if !access.ValidID(id) || !access.ValidID(trace) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return e
	}
	var client, state string
	var version uint64
	if e = tx.QueryRowContext(ctx, `SELECT client_id,key_version,state FROM keygate.recovery_tasks WHERE environment=$1 AND recovery_id=$2`, c.environment, id).Scan(&client, &version, &state); e != nil {
		return e
	}
	if !c.has(ctx, tx, a.id, access.EmergencyOperator, client) {
		return ErrDenied
	}
	if state == "completed" {
		return ErrConflict
	}
	if state == "aborted" {
		return tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='disabled' WHERE environment=$1 AND client_id=$2 AND version=$3 AND state<>'compromised'`, c.environment, client, version); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.clients SET state='disabled',revision=revision+1 WHERE environment=$1 AND client_id=$2`, c.environment, client); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.recovery_tasks SET state='aborted',finished_at=clock_timestamp() WHERE environment=$1 AND recovery_id=$2`, c.environment, id); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, a.id, "recovery_abort", id, "aborted"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.WarnContext(ctx, "隔离恢复任务已中止", "request_id", trace, "recovery_id", id, "client_id", client, "result", "aborted")
	return nil
}
