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

//go:embed browser_schema.sql
var browserSchema string

//go:embed login_freshness_schema.sql
var loginFreshnessSchema string

//go:embed native_mfa_schema.sql
var nativeMFASchema string

//go:embed local_accounts_schema.sql
var localAccountsSchema string

//go:embed trust_chain_schema.sql
var trustChainSchema string

//go:embed multiple_trust_roots_schema.sql
var multipleTrustRootsSchema string

//go:embed trust_history_schema.sql
var trustHistorySchema string

//go:embed trust_renewal_schema.sql
var trustRenewalSchema string

//go:embed governance_schema.sql
var governanceSchema string

//go:embed account_maintenance_schema.sql
var accountMaintenanceSchema string

//go:embed persistent_runtime_schema.sql
var persistentRuntimeSchema string

//go:embed approval_notifications_schema.sql
var approvalNotificationsSchema string

//go:embed notification_operations_schema.sql
var notificationOperationsSchema string

//go:embed system_monitor_schema.sql
var systemMonitorSchema string

func controlMigrations() []struct {
	version int
	body    string
} {
	return []struct {
		version int
		body    string
	}{{1, controlSchema}, {2, workflowSchema}, {3, keysSchema}, {4, lifecycleSchema}, {5, revocationSchema}, {6, recoverySchema}, {7, auditSchema}, {8, auditRefinementsSchema}, {9, providersSchema}, {10, clusterSchema}, {11, browserSchema}, {12, loginFreshnessSchema}, {13, nativeMFASchema}, {14, localAccountsSchema}, {15, trustChainSchema}, {16, multipleTrustRootsSchema}, {17, trustHistorySchema}, {18, trustRenewalSchema}, {19, governanceSchema}, {20, accountMaintenanceSchema}, {21, persistentRuntimeSchema}, {22, approvalNotificationsSchema}, {23, notificationOperationsSchema}, {24, systemMonitorSchema}}
}

// migrateControl 使用编号和校验和拒绝已应用迁移被静默修改；不自动降级。
func migrateControl(ctx context.Context, tx *sql.Tx) error {
	for _, m := range controlMigrations() {
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
