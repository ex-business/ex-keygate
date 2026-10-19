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

type Store struct {
	db   *sql.DB
	node *NodePermit
}

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &Store{db: db}, nil
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
	// 旧版初始化 DDL 只在首次建立迁移账本时执行；重复 ALTER 会与其他实例会话事务交叉死锁。
	// 编号迁移 1 和旧表在同一事务完成，已存在版本 1 即代表初始化成功，之后仍逐条验证校验和。
	var tracked bool
	if err = tx.QueryRowContext(ctx, `SELECT to_regclass('keygate.schema_migrations') IS NOT NULL`).Scan(&tracked); err != nil {
		return err
	}
	initialized := false
	if tracked {
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.schema_migrations WHERE version=1)`).Scan(&initialized); err != nil {
			return err
		}
	}
	if !initialized {
		if _, err = tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS keygate.schema_migrations(version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
			return err
		}
	}
	if err = migrateControl(ctx, tx); err != nil {
		return err
	}
	// 保留历史未绑定会话的撤销保障，但不再为此重复 ALTER 有效会话表。
	if _, err = tx.ExecContext(ctx, `UPDATE keygate.sessions SET revoked_at=clock_timestamp() WHERE profile_hash='0000000000000000000000000000000000000000000000000000000000000000' AND revoked_at IS NULL`); err != nil {
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

// ConsumeNonce 使用共享唯一约束作防重放决策，调用前必须验证签名及完整接受时间窗。
// validUntil 由服务端包含时钟偏差的接受窗口推导，不能由客户端独立选择；到期后拒绝原请求。
// 节点资格与 nonce 消费共用事务，提交不明视为拒绝，不允许盲目重试后放行。
func (s *Store) ConsumeNonce(ctx context.Context, scope Scope, nonce []byte, validUntil time.Time) (bool, error) {
	if s == nil || s.db == nil || !scope.valid() || len(nonce) != 32 || validUntil.IsZero() {
		return false, ErrInvalid
	}
	scopeBytes, _ := json.Marshal(scope)
	sh := sha256.Sum256(scopeBytes)
	nh := sha256.Sum256(nonce)
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO keygate.replay_nonces(scope_hash,nonce_hash,expires_at)
 SELECT $1,$2,$3 WHERE $3::timestamptz > clock_timestamp()
 AND $3::timestamptz <= clock_timestamp()+interval '5 minutes'
 ON CONFLICT DO NOTHING`, sh[:], nh[:], validUntil)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return count == 1, nil
}

// PruneNonces 只删除数据库时钟已判定过期的记录；清理后认证器仍须拒绝旧签名时间。
func (s *Store) PruneNonces(ctx context.Context) (int64, error) {
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM keygate.replay_nonces WHERE expires_at < clock_timestamp()")
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
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

// RegisterRootBudget 仅供受控根初始化，禁止重置已有用量或提高上限；登记也核验当前节点资格。
func (s *Store) RegisterRootBudget(ctx context.Context, rootID string, maximum int64, a Audit) error {
	if !identifier.MatchString(rootID) || maximum < 1 || maximum > 1<<30 || !a.valid() || a.TargetID != rootID || a.Action != "root_budget_register" || a.Result != "success" {
		return ErrInvalid
	}
	tx, err := s.beginRuntime(ctx)
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

// ReserveWrappingUse 在加密之前提交共享用量及审计；加密失败或结果不明不退还额度。
// 同一实际根在所有节点必须使用同一不可变 rootID，不能通过重启节点重置预算。
func (s *Store) ReserveWrappingUse(ctx context.Context, rootID string, a Audit) error {
	if !identifier.MatchString(rootID) || !a.valid() || a.TargetID != rootID || a.Action != "root_wrap_reserve" || a.Result != "reserved" {
		return ErrInvalid
	}
	tx, err := s.beginRuntime(ctx)
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
