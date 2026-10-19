// Package storage implements PostgreSQL-backed shared security state.
// It is not an authorization layer; callers must supply verified identities.
package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed schema.sql
var schema string
var (
	ErrInvalid = errors.New("invalid security state input")
	ErrBudget  = errors.New("root key usage budget unavailable")
)
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Store struct{ db *sql.DB }

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &Store{db}, nil
}

// Migrate is explicit, never performed by an ordinary authentication request.
// The supplied connection must use a migration identity, not the runtime role.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 串行执行迁移和校验和检查，避免多个部署任务并发修改安全表。
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(610847122)"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, schema); err != nil {
		return err
	}
	if err = migrateControl(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

type Scope struct {
	Environment, ClientID, KeyID string
	Version                      uint64
}

func (s Scope) valid() bool {
	return identifier.MatchString(s.Environment) && identifier.MatchString(s.ClientID) && identifier.MatchString(s.KeyID) && s.Version > 0
}

// ConsumeNonce is the atomic replay decision shared by every participating node.
// Signature and signed timestamp validity must be checked before calling it.
// validUntil is derived by the server from the full acceptance window, including
// clock skew; it must never be an independently client-selected expiry.
// The authenticator must not accept this request at or after validUntil.
// A commit error is a denial, not permission to authenticate or blindly retry.
func (s *Store) ConsumeNonce(ctx context.Context, scope Scope, nonce []byte, validUntil time.Time) (bool, error) {
	if s == nil || s.db == nil || !scope.valid() || len(nonce) != 32 || validUntil.IsZero() {
		return false, ErrInvalid
	}
	scopeBytes, _ := json.Marshal(scope)
	sh := sha256.Sum256(scopeBytes)
	nh := sha256.Sum256(nonce)
	result, err := s.db.ExecContext(ctx, `INSERT INTO keygate.replay_nonces(scope_hash,nonce_hash,expires_at)
 SELECT $1,$2,$3 WHERE $3::timestamptz > clock_timestamp()
 AND $3::timestamptz <= clock_timestamp()+interval '5 minutes'
 ON CONFLICT DO NOTHING`, sh[:], nh[:], validUntil)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1 && err == nil, err
}

// PruneNonces removes only records already expired according to the database.
// Authenticators must reject old signed timestamps even after these rows vanish.
func (s *Store) PruneNonces(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM keygate.replay_nonces WHERE expires_at < clock_timestamp()")
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type Audit struct{ EventID, RequestID, ActorID, Action, TargetID, Result string }

func (a Audit) valid() bool {
	for _, v := range []string{a.EventID, a.RequestID, a.ActorID, a.Action, a.TargetID, a.Result} {
		if !identifier.MatchString(v) {
			return false
		}
	}
	return true
}
func appendAudit(ctx context.Context, tx *sql.Tx, a Audit) error {
	if !a.valid() {
		return ErrInvalid
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO keygate.audit_events(event_id,request_id,actor_id,action,target_id,result) VALUES($1,$2,$3,$4,$5,$6)`, a.EventID, a.RequestID, a.ActorID, a.Action, a.TargetID, a.Result)
	if err != nil {
		return err
	}
	// 软件根预算预留也进入对应域的可靠归档队列，不把独立事务用量事实遗漏在生命周期审计之外。
	if a.Action == "root_wrap_reserve" {
		_, err = tx.ExecContext(ctx, `INSERT INTO keygate.scoped_audit(event_id,environment,client_id) SELECT $1,environment,'' FROM keygate.client_roots WHERE root_id=$2`, a.EventID, a.TargetID)
	}
	return err
}

// RegisterRootBudget belongs to a protected provisioning flow. It cannot change
// an existing root's usage or raise its limit; retries do not reset the counter.
func (s *Store) RegisterRootBudget(ctx context.Context, rootID string, maximum int64, a Audit) error {
	if !identifier.MatchString(rootID) || maximum < 1 || maximum > 1<<30 || !a.valid() || a.TargetID != rootID || a.Action != "root_budget_register" || a.Result != "success" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO keygate.root_budgets(root_id,maximum) VALUES($1,$2)", rootID, maximum); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}

// ReserveWrappingUse commits before encryption. Failed/uncertain encryption
// conservatively consumes the reservation; this API deliberately has no refund.
func (s *Store) ReserveWrappingUse(ctx context.Context, rootID string, a Audit) error {
	if !identifier.MatchString(rootID) || !a.valid() || a.TargetID != rootID || a.Action != "root_wrap_reserve" || a.Result != "reserved" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var used int64
	err = tx.QueryRowContext(ctx, "UPDATE keygate.root_budgets SET used=used+1 WHERE root_id=$1 AND used<maximum RETURNING used", rootID).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBudget
	}
	if err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return fmt.Errorf("reserve audit: %w", err)
	}
	return tx.Commit()
}
