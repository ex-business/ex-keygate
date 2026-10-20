package storage

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"ex-keygate/internal/access"
	"slices"
	"time"
)

type ApprovalNotification struct {
	ID          string    `json:"id"`
	RequestID   string    `json:"requestId"`
	RecipientID string    `json:"recipientId"`
	Kind        string    `json:"kind"`
	Digest      string    `json:"digest"`
	ExpiresAt   time.Time `json:"expiresAt"`
	CreatedAt   time.Time `json:"createdAt"`
	Read        bool      `json:"read"`
	State       string    `json:"state"`
	Attempts    int       `json:"attempts"`
}
type ApprovalNotificationPlugin interface {
	SendApprovalNotification(context.Context, ApprovalNotification) error
}

// WithdrawRequest 仅原申请人近期验证后撤回未执行的当前申请；与投票、执行共用域锁及请求行锁，历史票和审计不删除。
func (c *DevelopmentControl) WithdrawRequest(ctx context.Context, token, id, digest, reason, trace string) (ControlRequest, error) {
	if !access.ValidID(id) || !access.ValidID(trace) || !validGovernanceReason(reason) {
		return ControlRequest{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return ControlRequest{}, e
	}
	defer tx.Rollback()
	r, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return r, e
	}
	if e = c.executionActor(ctx, tx, token, m); e != nil {
		return ControlRequest{}, e
	}
	if subtle.ConstantTimeCompare([]byte(r.Digest), []byte(digest)) != 1 {
		return ControlRequest{}, ErrConflict
	}
	if r.Decision == "cancelled" && r.WithdrawnBy == m.Applicant.PrincipalID {
		if r.WithdrawalReason != reason {
			return ControlRequest{}, ErrConflict
		}
		return r, tx.Commit()
	}
	if r.Executed || r.Expired || r.Invalidated || (r.Decision != "pending" && r.Decision != "approved") {
		return ControlRequest{}, ErrConflict
	}
	var started bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.control_executions WHERE environment=$1 AND request_id=$2)`, c.environment, id).Scan(&started); e != nil {
		return r, e
	}
	if started {
		return r, ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET decision='cancelled',withdrawn_by=$3,withdrawal_reason=$4,withdrawn_at=clock_timestamp() WHERE environment=$1 AND request_id=$2`, c.environment, id, m.Applicant.PrincipalID, reason); e != nil {
		return r, e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.mfa_challenges WHERE environment=$1 AND purpose=$2`, c.environment, id); e != nil {
		return r, e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.mfa_proofs WHERE environment=$1 AND purpose=$2`, c.environment, id); e != nil {
		return r, e
	}
	if e = c.audit(ctx, tx, trace, m.Applicant.PrincipalID, "control_withdraw", id, "withdrawn"); e != nil {
		return r, e
	}
	if e = c.syncApprovalNotifications(ctx, tx, id); e != nil {
		return r, e
	}
	r, _, e = c.loadRequest(ctx, tx, id)
	if e != nil {
		return r, e
	}
	if e = tx.Commit(); e != nil {
		return ControlRequest{}, e
	}
	c.logger.InfoContext(ctx, "原申请人已撤回申请，旧票不再允许执行", "request_id", trace, "approval_id", id, "principal_id", m.Applicant.PrincipalID, "result", "withdrawn")
	return r, nil
}

func (c *DevelopmentControl) noticeRecipient(ctx context.Context, tx *sql.Tx, m controlManifest, id string) (bool, error) {
	if id == m.Applicant.PrincipalID {
		current, e := c.eligible(ctx, tx, id, access.Requester, operationScope(m.Operation))
		if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		if current != m.Applicant {
			return false, nil
		}
		if m.ProviderAdmin != nil {
			current, e = c.eligible(ctx, tx, id, access.PolicyAdmin, "")
			if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			if current != *m.ProviderAdmin {
				return false, nil
			}
		}
		return true, nil
	}
	_, e := c.currentMember(ctx, tx, m, id)
	if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
		return false, nil
	}
	return e == nil, e
}
func noticeTerminalKind(r ControlRequest) string {
	switch {
	case r.Executed:
		return "approval_executed"
	case r.Decision == "cancelled" && r.WithdrawnBy != "":
		return "approval_withdrawn"
	case r.Decision == "cancelled":
		return "approval_invalidated"
	case r.Decision == "rejected":
		return "approval_rejected"
	case r.Invalidated:
		return "approval_invalidated"
	case r.Expired:
		return "approval_expired"
	}
	return ""
}
func (c *DevelopmentControl) desiredNotices(ctx context.Context, tx *sql.Tx, r ControlRequest, m controlManifest) (map[string][]string, error) {
	out := map[string][]string{}
	kind := noticeTerminalKind(r)
	if kind != "" {
		out[kind] = []string{m.Applicant.PrincipalID}
		for _, a := range m.Approvers {
			out[kind] = append(out[kind], a.PrincipalID)
		}
		return out, nil
	}
	if r.Decision == "approved" {
		out["approval_ready"] = []string{m.Applicant.PrincipalID}
	} else if r.Decision == "pending" {
		if r.Progress != nil && r.Progress.CurrentPrincipalID != "" {
			out["approval_turn"] = []string{r.Progress.CurrentPrincipalID}
		} else if !m.Sequential {
			for _, a := range m.Approvers {
				var voted bool
				if e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.control_votes WHERE environment=$1 AND request_id=$2 AND principal_id=$3)`, c.environment, r.ID, a.PrincipalID).Scan(&voted); e != nil {
					return nil, e
				}
				if !voted {
					out["approval_turn"] = append(out["approval_turn"], a.PrincipalID)
				}
			}
		}
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return nil, e
	}
	expires, e := time.Parse(time.RFC3339Nano, m.Expires)
	if e != nil {
		return nil, e
	}
	if expires.Sub(now) <= time.Minute {
		out["approval_due"] = append([]string{m.Applicant.PrincipalID}, out["approval_turn"]...)
	}
	return out, nil
}

// syncApprovalNotifications 与审批状态变更同事务落队列；只含申请标识，不带操作载荷、恢复码、密码或任意收件地址。
func (c *DevelopmentControl) syncApprovalNotifications(ctx context.Context, tx *sql.Tx, id string) error {
	r, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return e
	}
	if noticeTerminalKind(r) == "" {
		if e = c.liveManifest(ctx, tx, m); errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
			r.Invalidated = true
		} else if e != nil {
			return e
		}
	}
	desired, e := c.desiredNotices(ctx, tx, r, m)
	if e != nil {
		return e
	}
	keep := []string{}
	for kind, recipients := range desired {
		for _, recipient := range recipients {
			allowed, e := c.noticeRecipient(ctx, tx, m, recipient)
			if e != nil {
				return e
			}
			if !allowed {
				continue
			}
			noticeID := digestBytes([]byte(c.environment + "\x00" + id + "\x00" + r.Digest + "\x00" + recipient + "\x00" + kind))
			keep = append(keep, noticeID)
			if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.approval_notifications(environment,id,request_id,recipient_id,kind,request_digest,expires_at) SELECT environment,$3,request_id,$4,$5,digest,expires_at FROM keygate.control_requests WHERE environment=$1 AND request_id=$2 ON CONFLICT DO NOTHING`, c.environment, id, noticeID, recipient, kind); e != nil {
				return e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.approval_notifications SET state='obsolete',lease_until=NULL WHERE environment=$1 AND request_id=$2 AND state IN ('pending','sending') AND NOT(id=ANY($3))`, c.environment, id, keep); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET notice_terminal=$3,notice_next_scan=clock_timestamp()+interval '10 seconds' WHERE environment=$1 AND request_id=$2`, c.environment, id, noticeTerminalKind(r) != "")
	return e
}

// CollectApprovalNotifications 由数据库时钟判断将到期和已超时，轮询游标避免旧终态申请阻塞新申请；绝不延长申请或自动审批。
func (c *DevelopmentControl) CollectApprovalNotifications(ctx context.Context) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.approval_notifications SET state='failed',lease_until=NULL WHERE environment=$1 AND state='sending' AND attempts>=5 AND lease_until<=clock_timestamp()`, c.environment); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, `SELECT request_id FROM keygate.control_requests WHERE environment=$1 AND NOT notice_terminal AND notice_next_scan<=clock_timestamp() ORDER BY notice_next_scan,request_id LIMIT 100 FOR UPDATE SKIP LOCKED`, c.environment)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = c.syncApprovalNotifications(ctx, tx, id); e != nil {
			return e
		}
	}
	return tx.Commit()
}

const noticeColumns = `id,request_id,recipient_id,kind,request_digest,expires_at,created_at,read_at IS NOT NULL,state,attempts`

func scanApprovalNotice(row reminderScanner) (ApprovalNotification, error) {
	var v ApprovalNotification
	e := row.Scan(&v.ID, &v.RequestID, &v.RecipientID, &v.Kind, &v.Digest, &v.ExpiresAt, &v.CreatedAt, &v.Read, &v.State, &v.Attempts)
	return v, e
}
func (c *DevelopmentControl) ApprovalNotifications(ctx context.Context, token string) ([]ApprovalNotification, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT `+noticeColumns+` FROM keygate.approval_notifications WHERE environment=$1 AND recipient_id=$2 ORDER BY created_at DESC,id DESC LIMIT 100`, c.environment, a.id)
	if e != nil {
		return nil, e
	}
	items := []ApprovalNotification{}
	for rows.Next() {
		v, e := scanApprovalNotice(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []ApprovalNotification{}
	for _, v := range items {
		_, m, e := c.loadRequest(ctx, tx, v.RequestID)
		if e != nil {
			return nil, e
		}
		allowed, e := c.noticeRecipient(ctx, tx, m, a.id)
		if e != nil {
			return nil, e
		}
		if allowed {
			out = append(out, v)
		}
	}
	return out, tx.Commit()
}
func (c *DevelopmentControl) ReadApprovalNotification(ctx context.Context, token, id string) error {
	if !validDigest(id) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return e
	}
	var request string
	if e = tx.QueryRowContext(ctx, `SELECT request_id FROM keygate.approval_notifications WHERE environment=$1 AND id=$2 AND recipient_id=$3`, c.environment, id, a.id).Scan(&request); e != nil {
		return ErrDenied
	}
	_, m, e := c.loadRequest(ctx, tx, request)
	if e != nil {
		return e
	}
	allowed, e := c.noticeRecipient(ctx, tx, m, a.id)
	if e != nil {
		return e
	}
	if !allowed {
		return ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.approval_notifications SET read_at=COALESCE(read_at,clock_timestamp()) WHERE environment=$1 AND id=$2 AND recipient_id=$3`, c.environment, id, a.id); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *DevelopmentControl) noticeCurrent(ctx context.Context, tx *sql.Tx, v ApprovalNotification) (bool, error) {
	r, m, e := c.loadRequest(ctx, tx, v.RequestID)
	if e != nil {
		return false, e
	}
	if r.Digest != v.Digest {
		return false, ErrConflict
	}
	if noticeTerminalKind(r) == "" {
		if e = c.liveManifest(ctx, tx, m); errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) {
			r.Invalidated = true
		} else if e != nil {
			return false, e
		}
	}
	desired, e := c.desiredNotices(ctx, tx, r, m)
	if e != nil {
		return false, e
	}
	if !slices.Contains(desired[v.Kind], v.RecipientID) {
		return false, nil
	}
	return c.noticeRecipient(ctx, tx, m, v.RecipientID)
}

// DispatchApprovalNotification 外部I/O不持域锁；同ID重试、尝试编号和租约约束迟到响应，最多5次后保留失败状态。
// 已发出的在途消息无法召回，只是提醒；收件人必须登录核对当前状态，不含任何执行凭证。
func (c *DevelopmentControl) DispatchApprovalNotification(ctx context.Context, plugin ApprovalNotificationPlugin) (bool, error) {
	if plugin == nil {
		return false, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	v, e := scanApprovalNotice(tx.QueryRowContext(ctx, `UPDATE keygate.approval_notifications SET state='sending',attempts=attempts+1,lease_until=clock_timestamp()+interval '30 seconds' WHERE environment=$1 AND id=(SELECT id FROM keygate.approval_notifications WHERE environment=$1 AND attempts<5 AND next_attempt<=clock_timestamp() AND (state='pending' OR (state='sending' AND lease_until<clock_timestamp())) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+noticeColumns, c.environment))
	if errors.Is(e, sql.ErrNoRows) {
		return false, tx.Commit()
	}
	if e != nil {
		return false, e
	}
	allowed, e := c.noticeCurrent(ctx, tx, v)
	if e != nil {
		return false, e
	}
	if !allowed {
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.approval_notifications SET state='obsolete',lease_until=NULL WHERE environment=$1 AND id=$2`, c.environment, v.ID); e != nil {
			return false, e
		}
		return true, tx.Commit()
	}
	if e = tx.Commit(); e != nil {
		return false, e
	}
	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	sendErr := plugin.SendApprovalNotification(sendCtx, v)
	cancel()
	tx, e = c.begin(ctx)
	if e != nil {
		return true, e
	}
	defer tx.Rollback()
	state := "sent"
	if sendErr != nil {
		state = "pending"
		if v.Attempts >= 5 {
			state = "failed"
		}
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.approval_notifications SET state=$4,lease_until=NULL,next_attempt=clock_timestamp()+($3*interval '30 seconds') WHERE environment=$1 AND id=$2 AND attempts=$3 AND state='sending'`, c.environment, v.ID, v.Attempts, state)
	if e != nil {
		return true, e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return true, e
	}
	if n == 1 {
		if e = c.audit(ctx, tx, "approval-notify-"+v.ID[:20], "approval-notifier", "approval_notification", v.RequestID, state); e != nil {
			return true, e
		}
	}
	if e = tx.Commit(); e != nil {
		return true, e
	}
	if sendErr != nil {
		c.logger.WarnContext(ctx, "审批通知投递未确认，将按同一幂等标识重试或保留失败", "notification_id", v.ID, "approval_id", v.RequestID, "attempt", v.Attempts, "result", state)
	}
	return true, nil
}
