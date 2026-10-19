package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"ex-keygate/internal/access"
	"ex-keygate/provider"
	"time"
)

const EnableProvider = "provider_enable"

type ProviderPolicySnapshot struct {
	ID       string `json:"id"`
	Digest   string `json:"digest"`
	Revision uint64 `json:"revision,string"`
}
type ProviderCandidate struct {
	Digest      string
	Binding     provider.Binding
	Implemented bool
}
type ProviderPolicy struct {
	ID, Digest string
	Enabled    bool
	Revision   uint64
	Candidates []ProviderCandidate
}

// seedBuiltInProviders 仅在新域初始化和编号迁移9中沿用原内部实现；重启或缺少记录不重新授权。
func seedBuiltInProviders(ctx context.Context, tx *sql.Tx, environment string) error {
	b := provider.InternalBinding()
	raw, digest, e := b.Encode()
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.provider_candidates(environment,provider_id,digest,binding,implemented) SELECT environment,$2,$3,$4,true FROM keygate.security_domains WHERE ($1='' OR environment=$1)`, environment, b.Descriptor.ID, digest, raw); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO keygate.provider_policies(environment,provider_id,active_digest,enabled) SELECT environment,$2,$3,true FROM keygate.security_domains WHERE ($1='' OR environment=$1)`, environment, b.Descriptor.ID, digest)
	return e
}
func (c *DevelopmentControl) RegisterProviderOffline(ctx context.Context, b provider.Binding, trace string) error {
	if !access.ValidID(trace) {
		return ErrInvalid
	}
	raw, digest, e := b.Encode()
	if e != nil {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var previous []byte
	e = tx.QueryRowContext(ctx, `SELECT binding FROM keygate.provider_candidates WHERE environment=$1 AND provider_id=$2 AND digest=$3`, c.environment, b.Descriptor.ID, digest).Scan(&previous)
	if e == nil {
		if string(previous) != string(raw) {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM keygate.provider_candidates WHERE environment=$1`, c.environment).Scan(&count); e != nil {
		return e
	}
	if count >= 64 {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.provider_candidates(environment,provider_id,digest,binding,implemented) VALUES($1,$2,$3,$4,$5)`, c.environment, b.Descriptor.ID, digest, raw, b.Executor != "reserved"); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.provider_policies(environment,provider_id,active_digest) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, c.environment, b.Descriptor.ID, digest); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, "offline-bootstrap", "provider_register", b.Descriptor.ID, "disabled"); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *DevelopmentControl) providerSnapshot(ctx context.Context, tx *sql.Tx, id string) (ProviderPolicySnapshot, error) {
	out := ProviderPolicySnapshot{ID: id}
	var enabled bool
	e := tx.QueryRowContext(ctx, `SELECT active_digest,revision,enabled FROM keygate.provider_policies WHERE environment=$1 AND provider_id=$2`, c.environment, id).Scan(&out.Digest, &out.Revision, &enabled)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrDenied
	}
	if e != nil {
		return out, e
	}
	if !enabled {
		return out, ErrDenied
	}
	return out, nil
}
func (c *DevelopmentControl) requireInternalProvider(ctx context.Context, tx *sql.Tx) error {
	snapshot, e := c.providerSnapshot(ctx, tx, "internal-software")
	if e != nil {
		return e
	}
	_, digest, _ := provider.InternalBinding().Encode()
	if snapshot.Digest != digest {
		return ErrDenied
	}
	return nil
}
func needsProviderSnapshot(kind string) bool {
	switch kind {
	case IssueKey, ActivateKey, RecoverIssue, RecoverActivate, ProvisionRoot:
		return true
	}
	return false
}
func (c *DevelopmentControl) validateProviderOperation(ctx context.Context, tx *sql.Tx, op ControlOperation) error {
	if op.ClientID != "provider-management" || !access.ValidID(op.ProviderID) || len(op.ProviderDigest) != 64 || op.ExpectedRevision == 0 || op.Name != "" || op.ProfileID != "" || op.ProfileVersion != 0 || op.KeyVersion != 0 || op.RootID != "" || op.RotationOf != 0 || op.RecipientPublicKey != "" || op.RecipientFingerprint != "" || op.RecipientSigningKey != "" || op.RecipientSigningFingerprint != "" || op.NotAfter != "" || op.RetireAt != "" {
		return ErrInvalid
	}
	var revision uint64
	var implemented bool
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT p.revision,c.implemented,c.binding FROM keygate.provider_policies p JOIN keygate.provider_candidates c ON c.environment=p.environment AND c.provider_id=p.provider_id AND c.digest=$3 WHERE p.environment=$1 AND p.provider_id=$2`, c.environment, op.ProviderID, op.ProviderDigest).Scan(&revision, &implemented, &raw)
	if e != nil {
		return e
	}
	if revision != op.ExpectedRevision {
		return ErrConflict
	}
	if !implemented {
		return ErrDenied
	}
	var b provider.Binding
	if json.Unmarshal(raw, &b) != nil || b.Validate() != nil || provider.Hash(raw) != op.ProviderDigest || b.Executor == "reserved" {
		return ErrDenied
	}
	return nil
}
func (c *DevelopmentControl) applyProviderOperation(ctx context.Context, tx *sql.Tx, op ControlOperation) error {
	r, e := tx.ExecContext(ctx, `UPDATE keygate.provider_policies SET active_digest=$3,enabled=true,revision=revision+1 WHERE environment=$1 AND provider_id=$2 AND revision=$4`, c.environment, op.ProviderID, op.ProviderDigest, op.ExpectedRevision)
	if e != nil {
		return e
	}
	return oneResult(r)
}
func (c *DevelopmentControl) Providers(ctx context.Context, token string) ([]ProviderPolicy, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	if !c.has(ctx, tx, a.id, access.Viewer, "") && !c.has(ctx, tx, a.id, access.PolicyAdmin, "") {
		return nil, ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT p.provider_id,p.active_digest,p.enabled,p.revision,c.digest,c.binding,c.implemented FROM keygate.provider_policies p JOIN keygate.provider_candidates c ON c.environment=p.environment AND c.provider_id=p.provider_id WHERE p.environment=$1 ORDER BY p.provider_id,c.created_at,c.digest LIMIT 64`, c.environment)
	if e != nil {
		return nil, e
	}
	out := []ProviderPolicy{}
	for rows.Next() {
		var p ProviderPolicy
		var candidate ProviderCandidate
		var raw []byte
		if e = rows.Scan(&p.ID, &p.Digest, &p.Enabled, &p.Revision, &candidate.Digest, &raw, &candidate.Implemented); e != nil {
			rows.Close()
			return nil, e
		}
		if json.Unmarshal(raw, &candidate.Binding) != nil || candidate.Binding.Validate() != nil || provider.Hash(raw) != candidate.Digest {
			rows.Close()
			return nil, ErrConflict
		}
		if len(out) == 0 || out[len(out)-1].ID != p.ID {
			p.Candidates = []ProviderCandidate{}
			out = append(out, p)
		}
		out[len(out)-1].Candidates = append(out[len(out)-1].Candidates, candidate)
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

// DisableProvider 是立即减权入口，递增插件修订使旧签发票与并发诊断结果全部失效，不回退其他插件。
func (c *DevelopmentControl) DisableProvider(ctx context.Context, token, id, trace string) error {
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
	if !c.has(ctx, tx, a.id, access.EmergencyOperator, "") {
		return ErrDenied
	}
	r, e := tx.ExecContext(ctx, `UPDATE keygate.provider_policies SET enabled=false,revision=revision+1 WHERE environment=$1 AND provider_id=$2`, c.environment, id)
	if e != nil {
		return e
	}
	if e = oneResult(r); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, a.id, "provider_disable", id, "disabled"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.WarnContext(ctx, "认证插件已停用", "request_id", trace, "provider_id", id, "result", "disabled")
	return nil
}

type ProviderCheck struct {
	State       string
	Conformance bool
	CheckedAt   time.Time
	Digest      string
	Revision    uint64
}

// CheckProvider 网络调用不持有域锁；回写前复核会话、管理员授权和插件修订，防止撤权或配置变更后接受晚到结果。
func (c *DevelopmentControl) CheckProvider(ctx context.Context, token, id, digest, trace string, check func(context.Context) (bool, error)) (ProviderCheck, error) {
	out := ProviderCheck{}
	if !access.ValidID(id) || !access.ValidID(trace) || len(digest) != 64 || check == nil {
		return out, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return out, e
	}
	admin, e := c.eligible(ctx, tx, a.id, access.PolicyAdmin, "")
	if e != nil {
		return out, e
	}
	snapshot, e := c.providerSnapshot(ctx, tx, id)
	if e != nil {
		return out, e
	}
	if snapshot.Digest != digest {
		return out, ErrConflict
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	conformance, callErr := check(bounded)
	if bounded.Err() != nil {
		callErr = bounded.Err()
		conformance = false
	}
	cancel()
	state := "ready"
	if callErr != nil {
		state = "unavailable"
		if errors.Is(callErr, provider.ErrRejected) {
			state = "rejected"
		}
		conformance = false
	}
	tx, e = c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	a, e = c.actor(ctx, tx, token, true)
	if e != nil {
		return out, e
	}
	current, e := c.eligible(ctx, tx, a.id, access.PolicyAdmin, "")
	if e != nil {
		return out, e
	}
	if current != admin {
		return out, ErrConflict
	}
	now, e := c.providerSnapshot(ctx, tx, id)
	if e != nil {
		return out, e
	}
	if now != snapshot {
		return out, ErrConflict
	}
	out = ProviderCheck{State: state, Conformance: conformance, Digest: digest, Revision: snapshot.Revision}
	if e = tx.QueryRowContext(ctx, `INSERT INTO keygate.provider_checks(environment,provider_id,digest,policy_revision,state,conformance) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(environment,provider_id) DO UPDATE SET digest=EXCLUDED.digest,policy_revision=EXCLUDED.policy_revision,state=EXCLUDED.state,conformance=EXCLUDED.conformance,checked_at=clock_timestamp() RETURNING checked_at`, c.environment, id, digest, snapshot.Revision, state, conformance).Scan(&out.CheckedAt); e != nil {
		return out, e
	}
	if e = c.audit(ctx, tx, trace, a.id, "provider_check", id, state); e != nil {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	return out, nil
}
func (c *DevelopmentControl) ProviderChecks(ctx context.Context, token string) (map[string]ProviderCheck, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	if !c.has(ctx, tx, a.id, access.Viewer, "") && !c.has(ctx, tx, a.id, access.PolicyAdmin, "") {
		return nil, ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT h.provider_id,h.state,h.conformance,h.checked_at,h.digest,h.policy_revision FROM keygate.provider_checks h JOIN keygate.provider_policies p ON p.environment=h.environment AND p.provider_id=h.provider_id AND p.revision=h.policy_revision AND p.active_digest=h.digest AND p.enabled WHERE h.environment=$1`, c.environment)
	if e != nil {
		return nil, e
	}
	out := map[string]ProviderCheck{}
	for rows.Next() {
		var id string
		var h ProviderCheck
		if e = rows.Scan(&id, &h.State, &h.Conformance, &h.CheckedAt, &h.Digest, &h.Revision); e != nil {
			rows.Close()
			return nil, e
		}
		out[id] = h
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

// CheckHealth 校验当前进程确实持有注册根且插件启用，不把声明的内部能力等同于可用密钥。
func (k *DevelopmentKeys) CheckHealth(ctx context.Context) error {
	c := k.control
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = c.requireInternalProvider(ctx, tx); e != nil {
		return e
	}
	if e = k.rootMatches(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}
