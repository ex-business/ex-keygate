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

//go:embed workflow_schema.sql
var workflowSchema string

//go:embed keys_schema.sql
var keysSchema string

//go:embed lifecycle_schema.sql
var lifecycleSchema string

//go:embed revocation_schema.sql
var revocationSchema string

//go:embed recovery_schema.sql
var recoverySchema string

//go:embed audit_schema.sql
var auditSchema string

//go:embed audit_refinements_schema.sql
var auditRefinementsSchema string

//go:embed providers_schema.sql
var providersSchema string

//go:embed cluster_schema.sql
var clusterSchema string

// migrateControl 使用编号和校验和拒绝已应用迁移被静默修改；不自动降级。
func migrateControl(ctx context.Context, tx *sql.Tx) error {
	for _, m := range []struct {
		version int
		body    string
	}{{1, controlSchema}, {2, workflowSchema}, {3, keysSchema}, {4, lifecycleSchema}, {5, revocationSchema}, {6, recoverySchema}, {7, auditSchema}, {8, auditRefinementsSchema}, {9, providersSchema}, {10, clusterSchema}} {
		hash := sha256.Sum256([]byte(m.body))
		checksum := hex.EncodeToString(hash[:])
		var existing string
		err := tx.QueryRowContext(ctx, `SELECT checksum FROM keygate.schema_migrations WHERE version=$1`, m.version).Scan(&existing)
		if err == nil {
			if existing != checksum {
				return fmt.Errorf("migration %d checksum mismatch", m.version)
			}
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		if _, err = tx.ExecContext(ctx, m.body); err != nil {
			return err
		}
		if m.version == 9 {
			if err = seedBuiltInProviders(ctx, tx, ""); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO keygate.schema_migrations(version,checksum) VALUES($1,$2)`, m.version, checksum); err != nil {
			return err
		}
	}
	return nil
}
