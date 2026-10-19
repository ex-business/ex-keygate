package storage

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var ErrLogin = errors.New("login transaction unavailable")
var ErrSession = errors.New("session unavailable")

type BrowserLoginContext struct {
	Environment string `json:"environment"`
	ClientID    string `json:"clientId"`
	Revision    uint64 `json:"revision,string"`
}

func (b BrowserLoginContext) valid() bool {
	return identifier.MatchString(b.Environment) && identifier.MatchString(b.ClientID) && b.Revision > 0
}

type LoginState struct {
	StartedAt      time.Time
	BrowserContext *BrowserLoginContext
	StateHash      [32]byte
	BrowserHash    [32]byte
	ProfileHash    string
	Nonce          string
	VerifierCipher []byte
}

func nonzero(h [32]byte) bool { return h != ([32]byte{}) }
func validNonce(n string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(n)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == n
}
func validDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

// 登录状态不保存浏览器秘密、原始 state 或明文 PKCE；调用者先按用途绑定加密，再与审计同事务保存。
func (s *Store) CreateLogin(ctx context.Context, state LoginState, a Audit) error {
	if !nonzero(state.StateHash) || !nonzero(state.BrowserHash) || !validDigest(state.ProfileHash) || !validNonce(state.Nonce) || len(state.VerifierCipher) == 0 || len(state.VerifierCipher) > 4096 || !a.valid() || a.ActorID != "anonymous" || a.Action != "login_create" || a.Result != "pending" || a.TargetID != hex.EncodeToString(state.StateHash[:]) {
		return ErrInvalid
	}
	var browserRaw []byte
	if state.BrowserContext != nil {
		if !state.BrowserContext.valid() {
			return ErrInvalid
		}
		browserRaw, _ = json.Marshal(state.BrowserContext)
	}
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO keygate.login_states(state_hash,browser_hash,profile_hash,nonce,verifier_cipher,browser_context) VALUES($1,$2,$3,$4,$5,$6)`, state.StateHash[:], state.BrowserHash[:], state.ProfileHash, state.Nonce, state.VerifierCipher, browserRaw)
	if err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeLogin 仅在浏览器秘密、固定身份配置及数据库有效期均匹配时原子消费；审计失败回滚。
// 提交不明时绝不返回 verifier，即使数据库可能已经消费，避免节点切换导致重复授权。
func (s *Store) ConsumeLogin(ctx context.Context, stateHash, browserHash [32]byte, profile string, a Audit) (LoginState, error) {
	if !nonzero(stateHash) || !nonzero(browserHash) || !validDigest(profile) || !a.valid() || a.ActorID != "anonymous" || a.Action != "login_consume" || a.Result != "consumed" || a.TargetID != hex.EncodeToString(stateHash[:]) {
		return LoginState{}, ErrInvalid
	}
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return LoginState{}, err
	}
	defer tx.Rollback()
	state := LoginState{StateHash: stateHash, BrowserHash: browserHash, ProfileHash: profile}
	var browserRaw []byte
	err = tx.QueryRowContext(ctx, `DELETE FROM keygate.login_states WHERE state_hash=$1 AND browser_hash=$2 AND profile_hash=$3 AND expires_at>clock_timestamp() RETURNING nonce,verifier_cipher,browser_context,started_at`, stateHash[:], browserHash[:], profile).Scan(&state.Nonce, &state.VerifierCipher, &browserRaw, &state.StartedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginState{}, ErrLogin
	}
	if err != nil {
		return LoginState{}, err
	}
	if len(browserRaw) > 0 {
		var b BrowserLoginContext
		if len(browserRaw) > 2048 || json.Unmarshal(browserRaw, &b) != nil || !b.valid() {
			return LoginState{}, ErrInvalid
		}
		state.BrowserContext = &b
	}
	if !validNonce(state.Nonce) || len(state.VerifierCipher) == 0 || len(state.VerifierCipher) > 4096 {
		return LoginState{}, ErrInvalid
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return LoginState{}, err
	}
	if err = tx.Commit(); err != nil {
		return LoginState{}, err
	}
	return state, nil
}

type Session struct {
	PrincipalID                string
	AuthenticatedAt, ExpiresAt time.Time
}

// 会话只建立身份，不赋予管理权限；绝对期限不能超过已核验认证时间之后五分钟。
// 创建、读取及撤销均核验权威节点资格，失效节点不能继续返回受保护会话。
func (s *Store) CreateSession(ctx context.Context, hash [32]byte, profile, principal string, auth time.Time, a Audit) (Session, error) {
	if !nonzero(hash) || !validDigest(profile) || !identifier.MatchString(principal) || auth.IsZero() || !a.valid() || a.ActorID != principal || a.Action != "session_create" || a.Result != "success" || a.TargetID != hex.EncodeToString(hash[:]) {
		return Session{}, ErrInvalid
	}
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	session, err := createSessionInTransaction(ctx, tx, hash, profile, principal, auth, a)
	if err != nil {
		return Session{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, err
	}
	return session, nil
}
func createSessionInTransaction(ctx context.Context, tx *sql.Tx, hash [32]byte, profile, principal string, auth time.Time, a Audit) (Session, error) {
	if !nonzero(hash) || !validDigest(profile) || !identifier.MatchString(principal) || auth.IsZero() || !a.valid() || a.ActorID != principal || a.Action != "session_create" || a.Result != "success" || a.TargetID != hex.EncodeToString(hash[:]) {
		return Session{}, ErrInvalid
	}
	var session Session
	err := tx.QueryRowContext(ctx, `INSERT INTO keygate.sessions(token_hash,principal_id,authenticated_at,expires_at,profile_hash)
 SELECT $1,$2,$3,LEAST($3::timestamptz+interval '5 minutes',clock_timestamp()+interval '5 minutes'),$4
 WHERE $3::timestamptz <= clock_timestamp()+interval '30 seconds' AND $3::timestamptz > clock_timestamp()-interval '5 minutes'
 RETURNING principal_id,authenticated_at,expires_at`, hash[:], principal, auth, profile).Scan(&session.PrincipalID, &session.AuthenticatedAt, &session.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSession
	}
	if err != nil {
		return Session{}, err
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return Session{}, err
	}
	return session, nil
}
func (s *Store) Session(ctx context.Context, hash [32]byte, profile string) (Session, error) {
	if !nonzero(hash) || !validDigest(profile) {
		return Session{}, ErrSession
	}
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	var session Session
	err = tx.QueryRowContext(ctx, `SELECT principal_id,authenticated_at,expires_at FROM keygate.sessions WHERE token_hash=$1 AND profile_hash=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, hash[:], profile).Scan(&session.PrincipalID, &session.AuthenticatedAt, &session.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSession
	}
	if err != nil {
		return Session{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, err
	}
	return session, nil
}
func (s *Store) RevokeSession(ctx context.Context, hash [32]byte, profile string, a Audit) error {
	if !nonzero(hash) || !validDigest(profile) || !a.valid() || a.Action != "session_revoke" || a.Result != "revoked" || a.TargetID != hex.EncodeToString(hash[:]) {
		return ErrInvalid
	}
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE keygate.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1 AND principal_id=$2 AND profile_hash=$3 AND revoked_at IS NULL`, hash[:], a.ActorID, profile)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrSession
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}
