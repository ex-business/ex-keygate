package storage

import (
	"context"
	"ex-keygate/internal/access"
	"time"
)

type LifecycleKey struct {
	RotationReason             string
	OriginalExpiryKnown        bool
	Version                    uint64
	State                      string
	NotAfter, OriginalNotAfter time.Time
	RetireAt                   *time.Time
	RotationID, RotationState  string
	Reminder                   bool
}

// Lifecycle 只暴露当前可读范围内的元数据；到期提醒只是事实提示，不会签发或延长有效期。
func (c *DevelopmentControl) Lifecycle(ctx context.Context, token, client string) ([]LifecycleKey, error) {
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
	rows, e := tx.QueryContext(ctx, `SELECT k.version,CASE WHEN k.state IN ('pending','staged','active','retiring') AND k.not_after<=clock_timestamp() THEN 'expired' ELSE k.state END,k.not_after,k.original_not_after,k.original_expiry_known,k.retire_at,COALESCE(t.issue_id,''),COALESCE(t.state,''),COALESCE(t.reason,''),k.state='active' AND k.not_after>clock_timestamp() AND k.not_after<=clock_timestamp()+interval '15 minutes' FROM keygate.key_versions k LEFT JOIN keygate.rotation_tasks t ON t.environment=k.environment AND t.client_id=k.client_id AND t.new_version=k.version WHERE k.environment=$1 AND k.client_id=$2 ORDER BY k.version DESC LIMIT 100`, c.environment, client)
	if e != nil {
		return nil, e
	}
	out := []LifecycleKey{}
	for rows.Next() {
		var k LifecycleKey
		if e = rows.Scan(&k.Version, &k.State, &k.NotAfter, &k.OriginalNotAfter, &k.OriginalExpiryKnown, &k.RetireAt, &k.RotationID, &k.RotationState, &k.RotationReason, &k.Reminder); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, k)
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

// MaintainLifecycle 是人工收尾入口，继续要求全域应急权限和近期会话。
func (c *DevelopmentControl) MaintainLifecycle(ctx context.Context, token, trace string) error {
	_, e := c.maintainLifecycle(ctx, token, trace, false)
	return e
}

// MaintainExpiredLifecycle 只供可信启动装配调用，不暴露 HTTP 执行权限；只收紧已按数据库时间失效的状态。
// 认证本身独立检查期限，维护停止、重试或并发运行都不能延长凭据有效期。
func (c *DevelopmentControl) MaintainExpiredLifecycle(ctx context.Context, trace string) (int64, error) {
	return c.maintainLifecycle(ctx, "", trace, true)
}
func (c *DevelopmentControl) maintainLifecycle(ctx context.Context, token, trace string, trusted bool) (int64, error) {
	if !access.ValidID(trace) {
		return 0, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	actor := "lifecycle-service"
	if !trusted {
		a, e := c.actor(ctx, tx, token, true)
		if e != nil {
			return 0, e
		}
		if !c.has(ctx, tx, a.id, access.EmergencyOperator, "") {
			return 0, ErrDenied
		}
		actor = a.id
	}
	changed := int64(0)
	result, e := tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='expired' WHERE environment=$1 AND state IN ('pending','staged','active','retiring') AND not_after<=clock_timestamp()`, c.environment)
	if e != nil {
		return 0, e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return 0, e
	}
	changed += n
	result, e = tx.ExecContext(ctx, `UPDATE keygate.rotation_tasks t SET state=CASE WHEN n.state='active' THEN 'completed' ELSE 'failed' END,completed_at=clock_timestamp() FROM keygate.key_versions n,keygate.key_versions o WHERE t.environment=$1 AND t.state IN ('preparing','overlap') AND n.environment=t.environment AND n.client_id=t.client_id AND n.version=t.new_version AND o.environment=t.environment AND o.client_id=t.client_id AND o.version=t.old_version AND ((t.state='overlap' AND o.state NOT IN ('active','retiring')) OR n.state IN ('disabled','expired','compromised') OR (n.state='pending' AND n.claim_expires<=clock_timestamp()))`, c.environment)
	if e != nil {
		return 0, e
	}
	n, e = result.RowsAffected()
	if e != nil {
		return 0, e
	}
	changed += n
	if changed > 0 || !trusted {
		if e = c.audit(ctx, tx, trace, actor, "lifecycle_maintain", c.environment, "success"); e != nil {
			return 0, e
		}
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return changed, nil
}
