package storage

import (
	"context"
	"ex-keygate/internal/access"
	"time"
)

type LifecycleKey struct {
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
	rows, e := tx.QueryContext(ctx, `SELECT k.version,CASE WHEN k.state IN ('pending','staged','active','retiring') AND k.not_after<=clock_timestamp() THEN 'expired' ELSE k.state END,k.not_after,k.original_not_after,k.original_expiry_known,k.retire_at,COALESCE(t.issue_id,''),COALESCE(t.state,''),k.state='active' AND k.not_after>clock_timestamp() AND k.not_after<=clock_timestamp()+interval '15 minutes' FROM keygate.key_versions k LEFT JOIN keygate.rotation_tasks t ON t.environment=k.environment AND t.client_id=k.client_id AND t.new_version=k.version WHERE k.environment=$1 AND k.client_id=$2 ORDER BY k.version DESC LIMIT 100`, c.environment, client)
	if e != nil {
		return nil, e
	}
	out := []LifecycleKey{}
	for rows.Next() {
		var k LifecycleKey
		if e = rows.Scan(&k.Version, &k.State, &k.NotAfter, &k.OriginalNotAfter, &k.OriginalExpiryKnown, &k.RetireAt, &k.RotationID, &k.RotationState, &k.Reminder); e != nil {
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

// MaintainLifecycle 只收紧已按数据库时间失效的状态；认证本身仍独立检查时间，不依赖维护任务存活。
func (c *DevelopmentControl) MaintainLifecycle(ctx context.Context, token, trace string) error {
	if !access.ValidID(trace) {
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
	if !c.has(ctx, tx, a.id, access.EmergencyOperator, "") {
		return ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='expired' WHERE environment=$1 AND state IN ('pending','staged','active','retiring') AND not_after<=clock_timestamp()`, c.environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.rotation_tasks t SET state=CASE WHEN n.state='active' THEN 'completed' ELSE 'failed' END,completed_at=clock_timestamp() FROM keygate.key_versions n,keygate.key_versions o WHERE t.environment=$1 AND t.state IN ('preparing','overlap') AND n.environment=t.environment AND n.client_id=t.client_id AND n.version=t.new_version AND o.environment=t.environment AND o.client_id=t.client_id AND o.version=t.old_version AND ((t.state='overlap' AND o.state NOT IN ('active','retiring')) OR n.state IN ('disabled','expired','compromised') OR (n.state='pending' AND n.claim_expires<=clock_timestamp()))`, c.environment); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, a.id, "lifecycle_maintain", c.environment, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
