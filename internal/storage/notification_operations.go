package storage

import (
	"context"
	"database/sql"
	"errors"
	"ex-keygate/internal/access"
	"time"
)

type DeliveryRecord struct {
	Round      int        `json:"round"`
	Attempt    int        `json:"attempt"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Outcome    string     `json:"outcome"`
	ActorID    string     `json:"actorId,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}
type NotificationAlert struct {
	Code          string    `json:"code"`
	Active        bool      `json:"active"`
	Count         int64     `json:"count"`
	OldestSeconds int64     `json:"oldestSeconds"`
	ChangedAt     time.Time `json:"changedAt"`
	CheckedAt     time.Time `json:"checkedAt"`
}
type NotificationOperations struct {
	Items     []ApprovalNotification `json:"items"`
	Alerts    []NotificationAlert    `json:"alerts"`
	More      bool                   `json:"more"`
	CanResend bool                   `json:"canResend"`
}

// 通知运维涉及全域人员标识，只允许全域审计员或策略管理员读取；局部角色不能越权查看全域队列。
func (c *DevelopmentControl) notificationOperator(ctx context.Context, tx *sql.Tx, token string, write bool) (controlActor, error) {
	a, e := c.actor(ctx, tx, token, write)
	if e != nil {
		return a, e
	}
	if !c.has(ctx, tx, a.id, access.PolicyAdmin, "") && (write || !c.has(ctx, tx, a.id, access.Auditor, "")) {
		return a, ErrDenied
	}
	return a, nil
}
func (c *DevelopmentControl) NotificationOperations(ctx context.Context, token, state string, offset int) (NotificationOperations, error) {
	out := NotificationOperations{Items: []ApprovalNotification{}, Alerts: []NotificationAlert{}}
	if offset < 0 || offset > 10000 {
		return out, ErrInvalid
	}
	switch state {
	case "", "pending", "sending", "sent", "failed", "obsolete":
	default:
		return out, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	a, e := c.notificationOperator(ctx, tx, token, false)
	if e != nil {
		return out, e
	}
	out.CanResend = c.has(ctx, tx, a.id, access.PolicyAdmin, "")
	rows, e := tx.QueryContext(ctx, `SELECT `+noticeColumns+` FROM keygate.approval_notifications WHERE environment=$1 AND ($2='' OR state=$2) ORDER BY created_at DESC,id DESC LIMIT 51 OFFSET $3`, c.environment, state, offset)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		v, e := scanApprovalNotice(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Items = append(out.Items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	out.More = len(out.Items) > 50
	if out.More {
		out.Items = out.Items[:50]
	}
	rows, e = tx.QueryContext(ctx, `SELECT code,active,count,oldest_seconds,changed_at,checked_at FROM keygate.approval_notification_alerts WHERE environment=$1 ORDER BY code`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var a NotificationAlert
		if e = rows.Scan(&a.Code, &a.Active, &a.Count, &a.OldestSeconds, &a.ChangedAt, &a.CheckedAt); e != nil {
			rows.Close()
			return out, e
		}
		out.Alerts = append(out.Alerts, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}
func (c *DevelopmentControl) NotificationDeliveryRecords(ctx context.Context, token, id string) ([]DeliveryRecord, error) {
	if !validDigest(id) {
		return nil, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = c.notificationOperator(ctx, tx, token, false); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT round,attempt,started_at,finished_at,outcome,actor_id,reason FROM keygate.approval_delivery_records WHERE environment=$1 AND notification_id=$2 ORDER BY round,attempt`, c.environment, id)
	if e != nil {
		return nil, e
	}
	out := []DeliveryRecord{}
	for rows.Next() {
		var r DeliveryRecord
		if e = rows.Scan(&r.Round, &r.Attempt, &r.StartedAt, &r.FinishedAt, &r.Outcome, &r.ActorID, &r.Reason); e != nil {
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
	return out, tx.Commit()
}

// ResendApprovalNotification 只重排失败且仍有效的原通知，保持插件幂等标识和载荷；冻结轮次防止并发点击或迟到确认覆盖新一轮。
// 最多人工重发三轮，每轮仍最多五次，不允许人工接管正在发送的任务或恢复失效任务。
func (c *DevelopmentControl) ResendApprovalNotification(ctx context.Context, token, id, digest, reason, trace string, expectedRound int) error {
	if !validDigest(id) || !validDigest(digest) || !access.ValidID(trace) || !validGovernanceReason(reason) || expectedRound < 0 || expectedRound >= 3 {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := c.notificationOperator(ctx, tx, token, true)
	if e != nil {
		return e
	}
	v, e := scanApprovalNotice(tx.QueryRowContext(ctx, `SELECT `+noticeColumns+` FROM keygate.approval_notifications WHERE environment=$1 AND id=$2 FOR UPDATE`, c.environment, id))
	if errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	}
	if e != nil {
		return e
	}
	if v.Digest != digest {
		return ErrConflict
	}
	// 相同人员、原因和预期轮次重复请求视为同一次操作，避免网络结果不明时重复加预算。
	if v.Resends == expectedRound+1 {
		var same bool
		e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.approval_delivery_records WHERE environment=$1 AND notification_id=$2 AND round=$3 AND attempt=0 AND actor_id=$4 AND reason=$5)`, c.environment, id, v.Resends, a.id, reason).Scan(&same)
		if e != nil {
			return e
		}
		if same {
			return tx.Commit()
		}
		return ErrConflict
	}
	if v.Resends != expectedRound || v.State != "failed" {
		return ErrConflict
	}
	current, e := c.noticeCurrent(ctx, tx, v)
	if e != nil {
		return e
	}
	if !current {
		return ErrConflict
	}
	var cooldown bool
	if e = tx.QueryRowContext(ctx, `SELECT last_resend_at IS NULL OR last_resend_at<=clock_timestamp()-interval '60 seconds' FROM keygate.approval_notifications WHERE environment=$1 AND id=$2`, c.environment, id).Scan(&cooldown); e != nil {
		return e
	}
	if !cooldown {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.approval_notifications SET state='pending',attempts=0,resend_count=resend_count+1,last_resend_at=clock_timestamp(),next_attempt=clock_timestamp(),lease_until=NULL WHERE environment=$1 AND id=$2`, c.environment, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.approval_delivery_records(environment,notification_id,round,attempt,outcome,actor_id,reason,finished_at) VALUES($1,$2,$3,0,'rescheduled',$4,$5,clock_timestamp())`, c.environment, id, expectedRound+1, a.id, reason); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, a.id, "approval_notification_resend", v.RequestID, "rescheduled"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.InfoContext(ctx, "审批通知已受控重排投递", "request_id", trace, "notification_id", id, "principal_id", a.id, "round", expectedRound+1, "result", "rescheduled")
	return nil
}

// 进程中断后将租约超时的尝试保留为未确认事实，绝不伪造插件成功或抹去原尝试。
func (c *DevelopmentControl) expireDeliveryRecords(ctx context.Context, tx *sql.Tx) error {
	_, e := tx.ExecContext(ctx, `UPDATE keygate.approval_delivery_records r SET outcome=CASE WHEN n.state='obsolete' THEN 'obsolete' ELSE 'lease_expired' END,finished_at=clock_timestamp() FROM keygate.approval_notifications n WHERE r.environment=$1 AND n.environment=r.environment AND n.id=r.notification_id AND r.outcome='sending' AND (n.state='obsolete' OR (n.state='sending' AND n.lease_until<=clock_timestamp()))`, c.environment)
	return e
}

// 固定阈值先覆盖开发运维：任何失败、待投递100条或最老超过5分钟、发送租约过期；状态变化才输出日志，避免持续故障刷屏。
func (c *DevelopmentControl) updateNotificationAlerts(ctx context.Context, tx *sql.Tx) ([]NotificationAlert, error) {
	changedAlerts := []NotificationAlert{}
	var pending, failed, stale, age int64
	e := tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state='pending'),count(*) FILTER(WHERE state='failed'),count(*) FILTER(WHERE state='sending' AND lease_until<=clock_timestamp()),COALESCE(EXTRACT(EPOCH FROM clock_timestamp()-min(created_at) FILTER(WHERE state='pending'))::bigint,0) FROM keygate.approval_notifications WHERE environment=$1`, c.environment).Scan(&pending, &failed, &stale, &age)
	if e != nil {
		return nil, e
	}
	for _, a := range []NotificationAlert{{Code: "backlog", Active: pending >= 100 || age >= 300, Count: pending, OldestSeconds: age}, {Code: "failed", Active: failed > 0, Count: failed}, {Code: "stale_lease", Active: stale > 0, Count: stale}} {
		var previous bool
		e = tx.QueryRowContext(ctx, `SELECT active FROM keygate.approval_notification_alerts WHERE environment=$1 AND code=$2`, c.environment, a.Code).Scan(&previous)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return nil, e
		}
		changed := previous != a.Active
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.approval_notification_alerts(environment,code,active,count,oldest_seconds) VALUES($1,$2,$3,$4,$5) ON CONFLICT(environment,code) DO UPDATE SET active=EXCLUDED.active,count=EXCLUDED.count,oldest_seconds=EXCLUDED.oldest_seconds,checked_at=clock_timestamp(),changed_at=CASE WHEN approval_notification_alerts.active<>EXCLUDED.active THEN clock_timestamp() ELSE approval_notification_alerts.changed_at END`, c.environment, a.Code, a.Active, a.Count, a.OldestSeconds); e != nil {
			return nil, e
		}
		if changed {
			changedAlerts = append(changedAlerts, a)
		}
	}
	return changedAlerts, nil
}
