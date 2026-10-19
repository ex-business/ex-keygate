package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

type BrowserSession struct {
	ClientID        string    `json:"clientId"`
	PrincipalID     string    `json:"principalId"`
	AuthenticatedAt time.Time `json:"authenticatedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

func browserTokenHash(token string) ([32]byte, error) {
	raw, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return [32]byte{}, ErrDenied
	}
	return sha256.Sum256([]byte(token)), nil
}

// CreateBrowserSession 只将已核验身份兑换为固定 H5 客户端会话，不赋予管理权限或业务角色。
// 同域锁冻结客户端与人员修订，期限继承原身份；重复建立撤销同父会话旧凭据，不延长认证时间。
func (c *DevelopmentControl) CreateBrowserSession(ctx context.Context, identityToken, clientID, newToken, oldToken string, expectedRevision uint64, trace string) (BrowserSession, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return BrowserSession{}, e
	}
	defer tx.Rollback()
	out, e := c.createBrowserSession(ctx, tx, identityToken, clientID, newToken, oldToken, expectedRevision, trace)
	if e != nil {
		return BrowserSession{}, e
	}
	if e = tx.Commit(); e != nil {
		return BrowserSession{}, e
	}
	c.logger.InfoContext(ctx, "H5客户端会话已建立", "request_id", trace, "client_id", clientID, "principal_id", out.PrincipalID, "result", "success")
	return out, nil
}
func (c *DevelopmentControl) createBrowserSession(ctx context.Context, tx *sql.Tx, identityToken, clientID, newToken, oldToken string, expectedRevision uint64, trace string) (BrowserSession, error) {
	out := BrowserSession{}
	if !identifier.MatchString(clientID) || !identifier.MatchString(trace) {
		return out, ErrInvalid
	}
	tokenHash, e := browserTokenHash(newToken)
	if e != nil {
		return out, ErrInvalid
	}
	identityHash, e := browserTokenHash(identityToken)
	if e != nil {
		return out, e
	}
	actor, e := c.identityActor(ctx, tx, identityToken, true)
	if e != nil {
		return out, e
	}
	var revision uint64
	e = tx.QueryRowContext(ctx, `SELECT c.revision FROM keygate.clients c JOIN keygate.auth_profiles p ON p.environment=c.environment AND p.profile_id=c.profile_id AND p.version=c.profile_version WHERE c.environment=$1 AND c.client_id=$2 AND c.state='enabled' AND c.client_type='browser' AND p.enabled AND p.client_type='browser' AND p.method='federated_session' AND p.storage='none' AND p.provider_id='oidc'`, c.environment, clientID).Scan(&revision)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrDenied
	}
	if e != nil {
		return out, e
	}
	if expectedRevision != 0 && revision != expectedRevision {
		return out, ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.browser_sessions SET revoked_at=clock_timestamp() WHERE environment=$1 AND client_id=$2 AND identity_hash=$3 AND revoked_at IS NULL`, c.environment, clientID, identityHash[:]); e != nil {
		return out, e
	}
	if oldToken != "" {
		oldHash, e := browserTokenHash(oldToken)
		if e != nil {
			return out, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.browser_sessions SET revoked_at=clock_timestamp() WHERE environment=$1 AND client_id=$2 AND token_hash=$3 AND revoked_at IS NULL`, c.environment, clientID, oldHash[:]); e != nil {
			return out, e
		}
	}
	out.ClientID = clientID
	out.PrincipalID = actor.id
	e = tx.QueryRowContext(ctx, `INSERT INTO keygate.browser_sessions(token_hash,environment,client_id,principal_id,identity_hash,profile_hash,client_revision,principal_revision,authenticated_at,expires_at) SELECT $1,$2,$3,$4,token_hash,$5,$6,$7,authenticated_at,expires_at FROM keygate.sessions WHERE token_hash=$8 AND revoked_at IS NULL AND expires_at>clock_timestamp() RETURNING authenticated_at,expires_at`, tokenHash[:], c.environment, clientID, actor.id, c.profile, revision, actor.revision, identityHash[:]).Scan(&out.AuthenticatedAt, &out.ExpiresAt)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrDenied
	}
	if e != nil {
		return out, e
	}
	if e = c.audit(ctx, tx, trace, actor.id, "browser_session_create", clientID, "success"); e != nil {
		return out, e
	}
	return out, nil
}

// browserSession 每次核对父身份撤销、人员与客户端修订及受控 Profile，停用再启用不能复活旧会话。
func (c *DevelopmentControl) browserSession(ctx context.Context, tx *sql.Tx, clientID, token string) (BrowserSession, error) {
	out := BrowserSession{ClientID: clientID}
	if !identifier.MatchString(clientID) {
		return out, ErrInvalid
	}
	h, e := browserTokenHash(token)
	if e != nil {
		return out, e
	}
	e = tx.QueryRowContext(ctx, `SELECT b.principal_id,b.authenticated_at,b.expires_at FROM keygate.browser_sessions b JOIN keygate.sessions s ON s.token_hash=b.identity_hash JOIN keygate.principals u ON u.environment=b.environment AND u.principal_id=b.principal_id JOIN keygate.clients c ON c.environment=b.environment AND c.client_id=b.client_id JOIN keygate.auth_profiles p ON p.environment=c.environment AND p.profile_id=c.profile_id AND p.version=c.profile_version WHERE b.environment=$1 AND b.client_id=$2 AND b.token_hash=$3 AND b.profile_hash=$4 AND b.revoked_at IS NULL AND b.expires_at>clock_timestamp() AND s.principal_id=b.principal_id AND s.profile_hash=$4 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.enabled AND u.revision=b.principal_revision AND c.state='enabled' AND c.revision=b.client_revision AND c.client_type='browser' AND p.enabled AND p.client_type='browser' AND p.method='federated_session' AND p.storage='none' AND p.provider_id='oidc' FOR UPDATE OF b,s,u`, c.environment, clientID, h[:], c.profile).Scan(&out.PrincipalID, &out.AuthenticatedAt, &out.ExpiresAt)
	if errors.Is(e, sql.ErrNoRows) {
		return BrowserSession{}, ErrDenied
	}
	return out, e
}
func (c *DevelopmentControl) BrowserSession(ctx context.Context, clientID, token string) (BrowserSession, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return BrowserSession{}, e
	}
	defer tx.Rollback()
	out, e := c.browserSession(ctx, tx, clientID, token)
	if e != nil {
		return BrowserSession{}, e
	}
	if e = tx.Commit(); e != nil {
		return BrowserSession{}, e
	}
	return out, nil
}

// AuthenticateBrowser 在最终权威事务核验会话并记录认证审计；结果只说明当前请求身份，不是可转移的 Bearer。
func (c *DevelopmentControl) AuthenticateBrowser(ctx context.Context, clientID, token, trace string) (BrowserSession, error) {
	if !identifier.MatchString(trace) {
		return BrowserSession{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return BrowserSession{}, e
	}
	defer tx.Rollback()
	out, e := c.browserSession(ctx, tx, clientID, token)
	if e != nil {
		return BrowserSession{}, e
	}
	if e = c.audit(ctx, tx, trace, out.PrincipalID, "browser_auth", clientID, "success"); e != nil {
		return BrowserSession{}, e
	}
	if e = tx.Commit(); e != nil {
		return BrowserSession{}, e
	}
	return out, nil
}

// RevokeBrowserSession 退出只减少权限，即使客户端已停用仍可撤销持有的凭据；不允许撤销其他客户端或主体的会话。
func (c *DevelopmentControl) RevokeBrowserSession(ctx context.Context, clientID, token, trace string) error {
	if !identifier.MatchString(clientID) || !identifier.MatchString(trace) {
		return ErrInvalid
	}
	h, e := browserTokenHash(token)
	if e != nil {
		return e
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var principal string
	e = tx.QueryRowContext(ctx, `UPDATE keygate.browser_sessions SET revoked_at=clock_timestamp() WHERE environment=$1 AND client_id=$2 AND token_hash=$3 AND profile_hash=$4 AND revoked_at IS NULL RETURNING principal_id`, c.environment, clientID, h[:], c.profile).Scan(&principal)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	}
	if e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, principal, "browser_logout", clientID, "revoked"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.InfoContext(ctx, "H5客户端会话已退出", "request_id", trace, "client_id", clientID, "principal_id", principal, "result", "revoked")
	return nil
}

// BrowserLoginSnapshot 匿名启动前仅检查已批准的 H5 客户端，冻结修订；回调兑换时再次核验，防止在途停用后继续登录。
func (c *DevelopmentControl) BrowserLoginSnapshot(ctx context.Context, clientID string) (BrowserLoginContext, error) {
	out := BrowserLoginContext{Environment: c.environment, ClientID: clientID}
	if !identifier.MatchString(clientID) {
		return out, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	e = tx.QueryRowContext(ctx, `SELECT c.revision FROM keygate.clients c JOIN keygate.auth_profiles p ON p.environment=c.environment AND p.profile_id=c.profile_id AND p.version=c.profile_version WHERE c.environment=$1 AND c.client_id=$2 AND c.state='enabled' AND c.client_type='browser' AND p.enabled AND p.client_type='browser' AND p.method='federated_session' AND p.storage='none' AND p.provider_id='oidc'`, c.environment, clientID).Scan(&out.Revision)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrDenied
	}
	if e != nil {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	return out, nil
}

// CompleteBrowserLogin 只接收服务端核验过的 OIDC 身份；父身份、H5会话及审计必须同事务成功，失败不留下半成品凭据。
func (c *DevelopmentControl) CompleteBrowserLogin(ctx context.Context, snapshot BrowserLoginContext, principal string, auth time.Time, identityToken, newToken, oldToken, trace string) (BrowserSession, error) {
	if !snapshot.valid() || snapshot.Environment != c.environment || !identifier.MatchString(trace) {
		return BrowserSession{}, ErrInvalid
	}
	identityHash, e := browserTokenHash(identityToken)
	if e != nil {
		return BrowserSession{}, ErrInvalid
	}
	event, e := controlID()
	if e != nil {
		return BrowserSession{}, e
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return BrowserSession{}, e
	}
	defer tx.Rollback()
	if _, e = createSessionInTransaction(ctx, tx, identityHash, c.profile, principal, auth, Audit{event, trace, principal, "session_create", hex.EncodeToString(identityHash[:]), "success"}); e != nil {
		return BrowserSession{}, e
	}
	out, e := c.createBrowserSession(ctx, tx, identityToken, snapshot.ClientID, newToken, oldToken, snapshot.Revision, trace)
	if e != nil {
		return BrowserSession{}, e
	}
	if e = tx.Commit(); e != nil {
		return BrowserSession{}, e
	}
	c.logger.InfoContext(ctx, "H5登录及身份会话已原子建立", "request_id", trace, "client_id", snapshot.ClientID, "principal_id", principal, "result", "success")
	return out, nil
}
