package storage

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

var ErrLogin = errors.New("login transaction unavailable")
var ErrSession = errors.New("session unavailable")

type LoginState struct {
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

// Login states never store raw browser/state secrets or plaintext PKCE verifiers.
// The caller must encrypt the verifier with scope-bound key protection first.
func (s *Store) CreateLogin(ctx context.Context, state LoginState, a Audit) error {
	if !nonzero(state.StateHash) || !nonzero(state.BrowserHash) || !validDigest(state.ProfileHash) || !validNonce(state.Nonce) || len(state.VerifierCipher) == 0 || len(state.VerifierCipher) > 4096 || !a.valid() || a.ActorID != "anonymous" || a.Action != "login_create" || a.Result != "pending" || a.TargetID != hex.EncodeToString(state.StateHash[:]) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO keygate.login_states(state_hash,browser_hash,profile_hash,nonce,verifier_cipher) VALUES($1,$2,$3,$4,$5)`, state.StateHash[:], state.BrowserHash[:], state.ProfileHash, state.Nonce, state.VerifierCipher)
	if err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeLogin deletes atomically only when the browser secret, fixed profile and
// database expiry all match. Audit failure rolls back deletion. Commit errors
// never return the verifier, even if the database may already have consumed it.
func (s *Store) ConsumeLogin(ctx context.Context, stateHash, browserHash [32]byte, profile string, a Audit) (LoginState, error) {
	if !nonzero(stateHash) || !nonzero(browserHash) || !validDigest(profile) || !a.valid() || a.ActorID != "anonymous" || a.Action != "login_consume" || a.Result != "consumed" || a.TargetID != hex.EncodeToString(stateHash[:]) {
		return LoginState{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoginState{}, err
	}
	defer tx.Rollback()
	state := LoginState{StateHash: stateHash, BrowserHash: browserHash, ProfileHash: profile}
	err = tx.QueryRowContext(ctx, `DELETE FROM keygate.login_states WHERE state_hash=$1 AND browser_hash=$2 AND profile_hash=$3 AND expires_at>clock_timestamp() RETURNING nonce,verifier_cipher`, stateHash[:], browserHash[:], profile).Scan(&state.Nonce, &state.VerifierCipher)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginState{}, ErrLogin
	}
	if err != nil {
		return LoginState{}, err
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

// A session establishes identity only, never local management permissions. Its
// absolute lifetime cannot extend beyond five minutes after the verified auth.
func (s *Store) CreateSession(ctx context.Context, hash [32]byte, principal string, auth time.Time, a Audit) (Session, error) {
	if !nonzero(hash) || !identifier.MatchString(principal) || auth.IsZero() || !a.valid() || a.ActorID != principal || a.Action != "session_create" || a.Result != "success" || a.TargetID != hex.EncodeToString(hash[:]) {
		return Session{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	var session Session
	err = tx.QueryRowContext(ctx, `INSERT INTO keygate.sessions(token_hash,principal_id,authenticated_at,expires_at)
 SELECT $1,$2,$3,LEAST($3::timestamptz+interval '5 minutes',clock_timestamp()+interval '5 minutes')
 WHERE $3::timestamptz <= clock_timestamp()+interval '30 seconds' AND $3::timestamptz > clock_timestamp()-interval '5 minutes'
 RETURNING principal_id,authenticated_at,expires_at`, hash[:], principal, auth).Scan(&session.PrincipalID, &session.AuthenticatedAt, &session.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSession
	}
	if err != nil {
		return Session{}, err
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return Session{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, err
	}
	return session, nil
}
func (s *Store) Session(ctx context.Context, hash [32]byte) (Session, error) {
	if !nonzero(hash) {
		return Session{}, ErrSession
	}
	var session Session
	err := s.db.QueryRowContext(ctx, `SELECT principal_id,authenticated_at,expires_at FROM keygate.sessions WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, hash[:]).Scan(&session.PrincipalID, &session.AuthenticatedAt, &session.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSession
	}
	return session, err
}
func (s *Store) RevokeSession(ctx context.Context, hash [32]byte, a Audit) error {
	if !nonzero(hash) || !a.valid() || a.Action != "session_revoke" || a.Result != "revoked" || a.TargetID != hex.EncodeToString(hash[:]) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE keygate.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1 AND principal_id=$2 AND revoked_at IS NULL`, hash[:], a.ActorID)
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
