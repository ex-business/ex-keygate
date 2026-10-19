package storage

import (
	"context"
	"database/sql"
	"errors"
	"ex-keygate/internal/access"
	"ex-keygate/internal/manifest"
)

type RevocationInput struct {
	IncidentID string `json:"incidentId"`
	ClientID   string `json:"clientId"`
	KeyVersion uint64 `json:"keyVersion,string"`
	RootID     string `json:"rootId"`
	Reason     string `json:"reason"`
}

func validReason(s string) bool {
	switch s {
	case "suspected_leak", "confirmed_leak", "lost_delivery", "scope_unknown":
		return true
	}
	return false
}

// Revoke 仅减权。版本撤销不影响无关版本，根撤销先阻断根并隔离所有依赖客户端，再记录子版本终态。
// 整个流程与认证共用域锁；所有事实、修订、任务失败和审计原子提交，响应丢失按相同事件号核对。
func (c *DevelopmentControl) Revoke(ctx context.Context, token string, in RevocationInput, trace string) error {
	if !access.ValidID(in.IncidentID) || !access.ValidID(trace) || !validReason(in.Reason) {
		return ErrInvalid
	}
	root := in.RootID != ""
	if root {
		if !access.ValidID(in.RootID) || in.ClientID != "" || in.KeyVersion != 0 {
			return ErrInvalid
		}
	} else if !access.ValidID(in.ClientID) || in.KeyVersion == 0 || in.KeyVersion > 9007199254740991 {
		return ErrInvalid
	}
	raw, e := manifest.Canonical(in)
	if e != nil {
		return ErrInvalid
	}
	digest := digestBytes(raw)
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return e
	}
	scope := in.ClientID
	if !c.has(ctx, tx, a.id, access.EmergencyOperator, scope) {
		return ErrDenied
	}
	var previous string
	e = tx.QueryRowContext(ctx, `SELECT parameters_digest FROM keygate.revocations WHERE environment=$1 AND incident_id=$2`, c.environment, in.IncidentID).Scan(&previous)
	if e == nil {
		if previous != digest {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if root {
		result, e := tx.ExecContext(ctx, `UPDATE keygate.client_roots SET enabled=false WHERE environment=$1 AND root_id=$2`, c.environment, in.RootID)
		if e != nil {
			return e
		}
		if e = oneResult(result); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.clients c SET state='disabled',revision=revision+1 WHERE c.environment=$1 AND EXISTS(SELECT 1 FROM keygate.key_versions k WHERE k.environment=c.environment AND k.client_id=c.client_id AND k.root_id=$2)`, c.environment, in.RootID); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='compromised' WHERE environment=$1 AND root_id=$2`, c.environment, in.RootID); e != nil {
			return e
		}
	} else {
		result, e := tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='compromised' WHERE environment=$1 AND client_id=$2 AND version=$3`, c.environment, in.ClientID, in.KeyVersion)
		if e != nil {
			return e
		}
		if e = oneResult(result); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.clients SET revision=revision+1 WHERE environment=$1 AND client_id=$2`, c.environment, in.ClientID); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.revocations(environment,incident_id,client_id,key_version,root_id,reason,actor_id,parameters_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.environment, in.IncidentID, in.ClientID, in.KeyVersion, in.RootID, in.Reason, a.id, digest); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.rotation_tasks t SET state='failed',completed_at=clock_timestamp() WHERE t.environment=$1 AND t.state IN ('preparing','overlap') AND EXISTS(SELECT 1 FROM keygate.key_versions k WHERE k.environment=t.environment AND k.client_id=t.client_id AND k.version IN(t.old_version,t.new_version) AND k.state='compromised')`, c.environment); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, a.id, "key_revoke", in.IncidentID, "compromised"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.WarnContext(ctx, "密钥泄露撤销已生效", "request_id", trace, "incident_id", in.IncidentID, "client_id", in.ClientID, "key_version", in.KeyVersion, "root_id", in.RootID, "reason", in.Reason, "result", "compromised")
	return nil
}
