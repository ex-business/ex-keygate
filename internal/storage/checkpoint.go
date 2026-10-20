package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"ex-keygate/internal/access"
	"time"
)

type SafetyCheckpoint struct {
	Kind        string                     `json:"kind"`
	Environment string                     `json:"environment"`
	ID          string                     `json:"id"`
	CapturedAt  time.Time                  `json:"capturedAt"`
	Tables      map[string]TableCheckpoint `json:"tables"`
}
type TableCheckpoint struct {
	Count  int64  `json:"count"`
	Digest string `json:"digest"`
}
type checkpointTable struct{ name, where string }

var checkpointTables = []checkpointTable{
	{"account_setups", "environment=$1"}, {"account_setup_factors", "environment=$1"},
	{"principal_session_blocks", "environment=$1"},
	{"runtime_cluster", "$1::text<>''"}, {"runtime_nodes", "$1::text<>''"},
	{"security_domains", "environment=$1"}, {"principals", "environment=$1"}, {"role_grants", "environment=$1"},
	{"auth_profiles", "environment=$1"}, {"clients", "environment=$1"}, {"control_policies", "environment=$1"}, {"control_policy_members", "environment=$1"},
	{"control_requests", "environment=$1"}, {"control_votes", "environment=$1"}, {"control_skips", "environment=$1"}, {"control_executions", "environment=$1"}, {"control_idempotency", "environment=$1"},
	{"client_roots", "environment=$1"}, {"key_versions", "environment=$1"}, {"rotation_tasks", "environment=$1"}, {"recovery_tasks", "environment=$1"}, {"revocations", "environment=$1"},
	{"provider_candidates", "environment=$1"}, {"provider_policies", "environment=$1"}, {"provider_checks", "environment=$1"},
	{"root_budgets", "root_id IN (SELECT root_id FROM keygate.client_roots WHERE environment=$1)"},
	{"mfa_policies", "environment=$1"}, {"mfa_factors", "environment=$1"}, {"mfa_challenges", "environment=$1"}, {"mfa_attempts", "environment=$1"}, {"mfa_proofs", "environment=$1"},
	{"application_trust_roots", "environment=$1"}, {"application_trust_services", "environment=$1"}, {"application_trust_certificates", "environment=$1"}, {"application_trust_changes", "environment=$1"}, {"application_trust_status_signers", "environment=$1"}, {"application_trust_status_changes", "environment=$1"}, {"application_trust_reminders", "environment=$1"},
	{"local_accounts", "environment=$1"}, {"local_login_budget", "environment=$1"},
	{"browser_sessions", "environment=$1"},
	{"sessions", "principal_id IN(SELECT principal_id FROM keygate.principals WHERE environment=$1)"},
	{"scoped_audit", "environment=$1"}, {"audit_events", "event_id IN(SELECT event_id FROM keygate.scoped_audit WHERE environment=$1)"},
	{"audit_outbox", "event_id IN(SELECT event_id FROM keygate.scoped_audit WHERE environment=$1)"},
	{"replay_nonces", "$1::text<>''"}, {"schema_migrations", "$1::text<>''"},
}

// captureSafety 同一快照覆盖撤销、票、执行、防重放和实际根预算；仅导出摘要，不导出凭据或密文。
// nonce 采用哈希作用域不能反查环境，因此保守覆盖全库；共享库其他域变化会导致校验失败而非误放行。
func captureSafety(ctx context.Context, tx *sql.Tx, environment string) (SafetyCheckpoint, error) {
	out := SafetyCheckpoint{Kind: "keygate-state-v1", Environment: environment, Tables: map[string]TableCheckpoint{}}
	if _, e := tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); e != nil {
		return out, e
	}
	if e := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&out.CapturedAt); e != nil {
		return out, e
	}
	for _, table := range checkpointTables {
		rows, e := tx.QueryContext(ctx, `SELECT to_jsonb(x)::text FROM (SELECT * FROM keygate.`+table.name+` WHERE `+table.where+`) x ORDER BY to_jsonb(x)::text COLLATE "C"`, environment)
		if e != nil {
			return out, e
		}
		h := sha256.New()
		var count int64
		for rows.Next() {
			var raw string
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return out, e
			}
			_, _ = h.Write([]byte(raw))
			_, _ = h.Write([]byte{'\n'})
			count++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		out.Tables[table.name] = TableCheckpoint{Count: count, Digest: hex.EncodeToString(h.Sum(nil))}
	}
	if out.Tables["security_domains"].Count != 1 {
		return out, ErrDenied
	}
	return out, nil
}
func (s *Store) CaptureSafetyCheckpoint(ctx context.Context, environment string) (SafetyCheckpoint, error) {
	if !access.ValidID(environment) {
		return SafetyCheckpoint{}, ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return SafetyCheckpoint{}, e
	}
	defer tx.Rollback()
	out, e := captureSafety(ctx, tx, environment)
	if e != nil {
		return out, e
	}
	out.ID, e = controlID()
	if e != nil {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	return out, nil
}
func matchingSafety(actual, expected SafetyCheckpoint) bool {
	if expected.Kind != "keygate-state-v1" || actual.Environment != expected.Environment || !access.ValidID(expected.ID) || expected.CapturedAt.IsZero() || len(actual.Tables) != len(expected.Tables) {
		return false
	}
	for name, table := range actual.Tables {
		if expected.Tables[name] != table {
			return false
		}
	}
	return true
}
func (s *Store) VerifySafetyCheckpoint(ctx context.Context, expected SafetyCheckpoint) error {
	actual, e := s.CaptureSafetyCheckpoint(ctx, expected.Environment)
	if e != nil {
		return e
	}
	if !matchingSafety(actual, expected) {
		return ErrConflict
	}
	return nil
}

// QuarantineRestored 仅在停止所有实例和隔离恢复库后由受控运维调用；不会重置根预算或重开初始化。
// 外部签名与“最新可信校验点”的保管由调用者先验证，本方法持锁比对后仅减权，绝不直接恢复认证。
func (s *Store) QuarantineRestored(ctx context.Context, expected SafetyCheckpoint, trace string) error {
	if !access.ValidID(expected.Environment) || !access.ValidID(trace) {
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// 与显式迁移共用排他运维锁，避免恢复锁表与迁移 DDL 的锁顺序交叉。
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(610847122)`); e != nil {
		return e
	}
	// 固定表清单阻止核对与隔离之间的写竞争；维护前必须停服。
	// 任一表仍被在线事务占用就立即拒绝并回滚全部锁，避免持有前序表锁等待后序表而形成锁环。
	for _, table := range checkpointTables {
		if _, e = tx.ExecContext(ctx, `LOCK TABLE keygate.`+table.name+` IN EXCLUSIVE MODE NOWAIT`); e != nil {
			return e
		}
	}
	actual, e := captureSafety(ctx, tx, expected.Environment)
	if e != nil {
		return e
	}
	if !matchingSafety(actual, expected) {
		return ErrConflict
	}
	// 恢复后推进全库节点代次，旧节点许可即使在备份中仍未过期也不能复用。
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.runtime_cluster SET generation=generation+1 WHERE singleton`); e != nil {
		return e
	}
	environment := expected.Environment
	// 隔离恢复必须同时作废已执行审批产生的一次性账号设置授权。
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.account_setups SET consumed=true WHERE environment=$1 AND NOT consumed`, environment); e != nil {
		return e
	}
	for _, table := range []string{"mfa_challenges", "mfa_proofs"} {
		if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.`+table+` WHERE environment=$1`, environment); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.application_trust_services SET disabled=true,revision=revision+1 WHERE environment=$1`, environment); e != nil {
		return e
	}

	if _, e = tx.ExecContext(ctx, `UPDATE keygate.browser_sessions SET revoked_at=clock_timestamp() WHERE environment=$1 AND revoked_at IS NULL`, environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.provider_policies SET enabled=false,revision=revision+1 WHERE environment=$1`, environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.clients SET state='disabled',revision=revision+1 WHERE environment=$1`, environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET decision='cancelled' WHERE environment=$1 AND NOT executed`, environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.sessions SET revoked_at=clock_timestamp() WHERE principal_id IN(SELECT principal_id FROM keygate.principals WHERE environment=$1) AND revoked_at IS NULL`, environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='disabled' WHERE environment=$1 AND state IN ('pending','staged')`, environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.recovery_tasks SET state='aborted',finished_at=clock_timestamp() WHERE environment=$1 AND state IN ('preparing','staged')`, environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.rotation_tasks SET state='failed',completed_at=clock_timestamp() WHERE environment=$1 AND state IN ('preparing','overlap')`, environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.audit_exports SET payload=''::bytea,expires_at=LEAST(expires_at,clock_timestamp()) WHERE environment=$1`, environment); e != nil {
		return e
	}
	event, e := controlID()
	if e != nil {
		return e
	}
	if e = appendAudit(ctx, tx, Audit{event, trace, "offline-recovery", "restore_quarantine", expected.ID, "disabled"}); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.scoped_audit(event_id,environment,client_id) VALUES($1,$2,'')`, event, environment); e != nil {
		return e
	}
	return tx.Commit()
}

// CheckQuarantinedOffline 供显式恢复启动验证已隔离状态；必须先由启动方验签并核对外部最新 checkpoint。
func (c *DevelopmentControl) CheckQuarantinedOffline(ctx context.Context) error {
	var safe bool
	e := c.store.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.security_domains WHERE environment=$1) AND EXISTS(SELECT 1 FROM keygate.scoped_audit s JOIN keygate.audit_events a ON a.event_id=s.event_id WHERE s.environment=$1 AND a.action='restore_quarantine') AND NOT EXISTS(SELECT 1 FROM keygate.account_setups WHERE environment=$1 AND NOT consumed) AND NOT EXISTS(SELECT 1 FROM keygate.mfa_proofs WHERE environment=$1) AND NOT EXISTS(SELECT 1 FROM keygate.mfa_challenges WHERE environment=$1) AND NOT EXISTS(SELECT 1 FROM keygate.browser_sessions WHERE environment=$1 AND revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM keygate.provider_policies WHERE environment=$1 AND enabled) AND NOT EXISTS(SELECT 1 FROM keygate.clients WHERE environment=$1 AND state='enabled') AND NOT EXISTS(SELECT 1 FROM keygate.control_requests WHERE environment=$1 AND NOT executed AND decision IN ('pending','approved')) AND NOT EXISTS(SELECT 1 FROM keygate.sessions WHERE principal_id IN(SELECT principal_id FROM keygate.principals WHERE environment=$1) AND revoked_at IS NULL)`, c.environment).Scan(&safe)
	if e != nil {
		return e
	}
	if !safe {
		return ErrDenied
	}
	return nil
}
