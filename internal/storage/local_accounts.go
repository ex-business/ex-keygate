package storage

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"ex-keygate/internal/password"
	"regexp"
	"time"
)

var accountName = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{2,127}$`)
var ErrCredentials = errors.New("账号或登录凭据不可用")

type LocalAccount struct {
	Username     string `json:"username"`
	PrincipalID  string `json:"principalId"`
	PasswordHash string `json:"passwordHash"`
}

// ProvisionLocalAccountsOffline 只接受已具备原生MFA绑定的人员，不创建人员或授予角色。
// 启动配置重复导入必须完全一致；口令恢复和换绑须另走受控流程，不静默覆盖。
func (c *DevelopmentControl) ProvisionLocalAccountsOffline(ctx context.Context, accounts []LocalAccount, request string) error {
	if len(accounts) == 0 || len(accounts) > 128 || !identifier.MatchString(request) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	seen := map[string]bool{}
	for _, a := range accounts {
		if !accountName.MatchString(a.Username) || !identifier.MatchString(a.PrincipalID) || seen[a.Username] {
			return ErrInvalid
		}
		seen[a.Username] = true
		if _, _, e = password.Parse(a.PasswordHash); e != nil {
			return ErrInvalid
		}
		var ready bool
		e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.principals p JOIN keygate.security_domains d USING(environment) JOIN keygate.mfa_policies m USING(environment,principal_id) WHERE p.environment=$1 AND p.principal_id=$2 AND p.enabled AND d.native_mfa_required)`, c.environment, a.PrincipalID).Scan(&ready)
		if e != nil {
			return e
		}
		if !ready {
			return ErrDenied
		}
		var p, h string
		e = tx.QueryRowContext(ctx, `SELECT principal_id,password_hash FROM keygate.local_accounts WHERE environment=$1 AND username=$2 FOR UPDATE`, c.environment, a.Username).Scan(&p, &h)
		if e == nil {
			if p != a.PrincipalID || h != a.PasswordHash {
				return ErrConflict
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.local_accounts(environment,username,principal_id,password_hash) VALUES($1,$2,$3,$4)`, c.environment, a.Username, a.PrincipalID, a.PasswordHash); e != nil {
			return e
		}
		if e = c.audit(ctx, tx, request, "offline-operator", "local_account_provision", a.PrincipalID, "success"); e != nil {
			return e
		}
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO keygate.local_login_budget(environment) VALUES($1) ON CONFLICT DO NOTHING`, c.environment)
	if e != nil {
		return e
	}
	return tx.Commit()
}

// PasswordSession 先在权威事务内消耗预算，再在事务外计算口令摘要；最终事务重新核对摘要与锁定状态。
// 全域每分钟最多60次，单账号连续5次失败锁定15分钟；多节点无法各自重置预算。
// 返回的是待二次验证会话，业务actor仍要求management用途的原生MFA证明。
func (c *DevelopmentControl) PasswordSession(ctx context.Context, username, value string, sessionHash, previousHash [32]byte, request string) (Session, error) {
	if !accountName.MatchString(username) || len(value) == 0 || len(value) > 1024 || !nonzero(sessionHash) || !identifier.MatchString(request) {
		return Session{}, ErrCredentials
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return Session{}, e
	}
	defer tx.Rollback()
	var allowed bool
	e = tx.QueryRowContext(ctx, `UPDATE keygate.local_login_budget SET attempts=CASE WHEN started_at<=clock_timestamp()-interval '1 minute' THEN 1 ELSE attempts+1 END,started_at=CASE WHEN started_at<=clock_timestamp()-interval '1 minute' THEN clock_timestamp() ELSE started_at END WHERE environment=$1 AND (attempts<60 OR started_at<=clock_timestamp()-interval '1 minute') RETURNING true`, c.environment).Scan(&allowed)
	if errors.Is(e, sql.ErrNoRows) {
		return Session{}, ErrCredentials
	}
	if e != nil {
		return Session{}, e
	}

	var snapshot string
	e = tx.QueryRowContext(ctx, `SELECT password_hash FROM keygate.local_accounts WHERE environment=$1 AND username=$2`, c.environment, username).Scan(&snapshot)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return Session{}, e
	}
	if e = c.audit(ctx, tx, request, "anonymous", "local_login_attempt", "local-login", "pending"); e != nil {
		return Session{}, e
	}
	if e = tx.Commit(); e != nil {
		return Session{}, e
	}
	// 计算不持有安全域锁；即使后续计算失败或请求取消，已消耗的共享预算也不会退回。
	matched := password.Verify(snapshot, value)
	tx, e = c.begin(ctx)
	if e != nil {
		return Session{}, e
	}
	defer tx.Rollback()
	var principal, encoded string
	var enabled, unlocked bool
	e = tx.QueryRowContext(ctx, `SELECT a.principal_id,a.password_hash,a.enabled AND p.enabled AND d.native_mfa_required AND EXISTS(SELECT 1 FROM keygate.mfa_policies m WHERE m.environment=a.environment AND m.principal_id=a.principal_id),a.locked_until<=clock_timestamp() FROM keygate.local_accounts a JOIN keygate.principals p USING(environment,principal_id) JOIN keygate.security_domains d USING(environment) WHERE a.environment=$1 AND a.username=$2 FOR UPDATE OF a`, c.environment, username).Scan(&principal, &encoded, &enabled, &unlocked)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return Session{}, e
	}
	matched = matched && encoded == snapshot

	if !matched || !enabled || !unlocked {
		if principal != "" && unlocked {
			_, e = tx.ExecContext(ctx, `UPDATE keygate.local_accounts SET failures=CASE WHEN failures>=5 THEN 1 ELSE failures+1 END,locked_until=CASE WHEN failures>=4 AND failures<5 THEN clock_timestamp()+interval '15 minutes' ELSE locked_until END WHERE environment=$1 AND username=$2`, c.environment, username)
			if e != nil {
				return Session{}, e
			}
		}
		if e = c.audit(ctx, tx, request, "anonymous", "local_login", "local-login", "denied"); e != nil {
			return Session{}, e
		}
		if e = tx.Commit(); e != nil {
			return Session{}, e
		}
		return Session{}, ErrCredentials
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.local_accounts SET failures=0 WHERE environment=$1 AND username=$2`, c.environment, username); e != nil {
		return Session{}, e
	}
	// 重新登录轮换浏览器会话，旧会话的MFA证明不能继承给新凭据。
	if nonzero(previousHash) {
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1 AND profile_hash=$2 AND revoked_at IS NULL`, previousHash[:], c.profile); e != nil {
			return Session{}, e
		}
	}
	var now time.Time
	if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return Session{}, e
	}
	target := hex.EncodeToString(sessionHash[:])
	out, e := createSessionInTransaction(ctx, tx, sessionHash, c.profile, principal, now, Audit{"event-" + target, request, principal, "session_create", target, "success"})
	if e != nil {
		return Session{}, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.sessions SET local_password=true WHERE token_hash=$1`, sessionHash[:]); e != nil {
		return Session{}, e
	}
	if e = tx.Commit(); e != nil {
		return Session{}, e
	}
	return out, nil
}

// requireLocalSessionMFA 将本地口令会话与当前绑定修订的MFA证明共同校验。
// H5兑换、持续认证及管理授权共用此门禁；关闭原生验证或停用账号也不会意外放行。
func (c *DevelopmentControl) requireLocalSessionMFA(ctx context.Context, tx *sql.Tx, h []byte) error {
	var valid bool
	e := tx.QueryRowContext(ctx, `SELECT NOT s.local_password OR EXISTS(
 SELECT 1 FROM keygate.local_accounts a JOIN keygate.principals p USING(environment,principal_id)
 JOIN keygate.security_domains d USING(environment) JOIN keygate.mfa_policies m USING(environment,principal_id)
 JOIN keygate.mfa_proofs f ON f.environment=a.environment AND f.principal_id=a.principal_id AND f.session_hash=s.token_hash
 WHERE a.environment=$1 AND a.principal_id=s.principal_id AND a.enabled AND p.enabled AND d.native_mfa_required
 AND f.purpose='management' AND f.principal_revision=p.revision AND f.policy_revision=m.revision AND f.expires_at>clock_timestamp())
 FROM keygate.sessions s WHERE s.token_hash=$2 AND s.profile_hash=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()`, c.environment, h, c.profile).Scan(&valid)
	if errors.Is(e, sql.ErrNoRows) || e == nil && !valid {
		return ErrDenied
	}
	return e
}
