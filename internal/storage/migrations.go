package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"fmt"
)

//go:embed control_schema.sql
var controlSchema string

// migrateControl 使用编号和校验和拒绝已应用迁移被静默修改；不自动降级。
func migrateControl(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS keygate.schema_migrations(version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(controlSchema))
	checksum := hex.EncodeToString(hash[:])
	var existing string
	err := tx.QueryRowContext(ctx, `SELECT checksum FROM keygate.schema_migrations WHERE version=1`).Scan(&existing)
	if err == nil {
		if existing != checksum {
			return fmt.Errorf("migration checksum mismatch")
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	if _, err = tx.ExecContext(ctx, controlSchema); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO keygate.schema_migrations(version,checksum) VALUES(1,$1)`, checksum)
	return err
}
