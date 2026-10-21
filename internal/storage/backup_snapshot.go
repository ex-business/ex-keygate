package storage

import (
	"context"
	"database/sql"
	"ex-keygate/internal/access"
)

// WithBackupSnapshot 仅适用于专用单域库：导出和检查点共享同一只读快照，回调结束前不释放供pg_dump导入的快照。
// 不能用先后两次独立查询声称备份与撤销事实一致；本方法不暂停认证，也不将备份放进认证事务。
func (s *Store) WithBackupSnapshot(ctx context.Context, environment string, export func(string, SafetyCheckpoint) error) error {
	if !access.ValidID(environment) || export == nil {
		return ErrInvalid
	}
	if e := CheckRuntimeSchema(ctx, s.db); e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var domains int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM keygate.security_domains`).Scan(&domains); e != nil {
		return e
	}
	if domains != 1 {
		return ErrConflict
	}
	var snapshot string
	if e = tx.QueryRowContext(ctx, `SELECT pg_export_snapshot()`).Scan(&snapshot); e != nil {
		return e
	}
	cp, e := captureSafety(ctx, tx, environment)
	if e != nil {
		return e
	}
	if cp.Tables["schema_migrations"].Count != RuntimeSchemaVersion {
		return ErrConflict
	}
	cp.ID, e = controlID()
	if e != nil {
		return e
	}
	if e = export(snapshot, cp); e != nil {
		return e
	}
	return tx.Commit()
}
