package storage

import (
	"context"
	"database/sql"
)

const RuntimeProtocol = 1
const RuntimeSchemaVersion = 22

type PersistentDeployment struct {
	Environment   string `json:"environment"`
	ID            string `json:"id"`
	Revision      uint64 `json:"revision"`
	ConfigHash    string `json:"configHash"`
	ProfileHash   string `json:"profileHash"`
	Protocol      int    `json:"protocol"`
	SchemaVersion int    `json:"schemaVersion"`
}

// CheckRuntimeSchema 普通启动只读核验完整账本及校验和；未知未来版本、缺失迁移均拒绝，不自动修改数据库。
func CheckRuntimeSchema(ctx context.Context, db *sql.DB) error {
	return CheckRuntimeSchemaVersion(ctx, db, RuntimeSchemaVersion)
}

// CheckRuntimeSchemaVersion 仅允许当前22及显式支持的21升级源，仍逐条核验完整账本而不写DDL。
func CheckRuntimeSchemaVersion(ctx context.Context, db *sql.DB, version int) error {
	if version != RuntimeSchemaVersion && version != 21 {
		return ErrConflict
	}
	tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var n, max int
	if e = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(max(version),0) FROM keygate.schema_migrations`).Scan(&n, &max); e != nil {
		return e
	}
	if n != version || max != version {
		return ErrConflict
	}
	for _, m := range controlMigrations() {
		if m.version > version {
			continue
		}
		var checksum string
		if e = tx.QueryRowContext(ctx, `SELECT checksum FROM keygate.schema_migrations WHERE version=$1`, m.version).Scan(&checksum); e != nil {
			return e
		}
		if checksum != digestBytes([]byte(m.body)) {
			return ErrConflict
		}
	}
	return tx.Commit()
}
func (s *Store) PersistentDeployment(ctx context.Context, environment string) (PersistentDeployment, error) {
	var d PersistentDeployment
	e := s.db.QueryRowContext(ctx, `SELECT environment,deployment_id,revision,config_hash,profile_hash,protocol,schema_version FROM keygate.persistent_deployments WHERE environment=$1`, environment).Scan(&d.Environment, &d.ID, &d.Revision, &d.ConfigHash, &d.ProfileHash, &d.Protocol, &d.SchemaVersion)
	return d, e
}
func validDeployment(d PersistentDeployment) bool {
	return identifier.MatchString(d.Environment) && identifier.MatchString(d.ID) && d.Revision > 0 && validDigest(d.ConfigHash) && validDigest(d.ProfileHash) && d.Protocol == RuntimeProtocol && d.SchemaVersion == RuntimeSchemaVersion
}

// RegisterPersistentDeploymentOffline 仅在首次域初始化完成后封存配置；已有域或已有集群绝不覆盖。
func (s *Store) RegisterPersistentDeploymentOffline(ctx context.Context, d PersistentDeployment, trace string) error {
	if !validDeployment(d) || d.Revision != 1 || !identifier.MatchString(trace) {
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var enabled bool
	if e = tx.QueryRowContext(ctx, `SELECT enabled FROM keygate.runtime_cluster WHERE singleton FOR UPDATE NOWAIT`).Scan(&enabled); e != nil {
		return e
	}
	if enabled {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.persistent_deployments(environment,deployment_id,revision,config_hash,profile_hash,protocol,schema_version) VALUES($1,$2,$3,$4,$5,$6,$7)`, d.Environment, d.ID, d.Revision, d.ConfigHash, d.ProfileHash, d.Protocol, d.SchemaVersion); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.runtime_cluster SET enabled=true,cluster_id=$1,configuration_hash=$2 WHERE singleton`, d.ID, d.ConfigHash); e != nil {
		return e
	}
	if e = appendAudit(ctx, tx, Audit{trace, trace, "offline-operator", "deployment_initialize", d.ID, "initialized"}); e != nil {
		return e
	}
	return tx.Commit()
}

// UpgradePersistentDeploymentOffline 必须停服并使用外部签名检查点；所有旧节点须摘流或租约过期，代次切换使旧配置不能重新加入。
// 检查点验证由调用者完成签名核验，此处在同一事务再次核对安全状态，避免检查与激活之间发生变更。
func (s *Store) UpgradePersistentDeploymentOffline(ctx context.Context, old, next PersistentDeployment, expected SafetyCheckpoint, trace string) error {
	if (old.SchemaVersion != 21 && old.SchemaVersion != RuntimeSchemaVersion) || !validDeployment(next) || old.Environment != next.Environment || old.ID != next.ID || next.Revision != old.Revision+1 || old.ProfileHash != next.ProfileHash || expected.Environment != old.Environment || !identifier.MatchString(trace) {
		return ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var id, hash string
	if e = tx.QueryRowContext(ctx, `SELECT cluster_id,configuration_hash FROM keygate.runtime_cluster WHERE singleton AND enabled FOR UPDATE NOWAIT`).Scan(&id, &hash); e != nil {
		return e
	}
	if id != old.ID || hash != old.ConfigHash {
		return ErrConflict
	}
	var live bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.runtime_nodes WHERE NOT drained AND expires_at>clock_timestamp())`).Scan(&live); e != nil {
		return e
	}
	if live {
		return ErrConflict
	}
	// 域锁与普通业务事务一致，检查点必须覆盖升级开始前的最后安全状态。
	if _, e = tx.ExecContext(ctx, `SELECT environment FROM keygate.security_domains WHERE environment=$1 FOR UPDATE NOWAIT`, old.Environment); e != nil {
		return e
	}
	current, e := captureSafety(ctx, tx, old.Environment)
	if e != nil {
		return e
	}
	if !matchingSafety(current, expected) {
		return ErrConflict
	}
	// 在同一事务核验旧检查点后执行唯一受支持的21->22迁移，失败时DDL、发布修订和代次整体回滚。
	if old.SchemaVersion == 21 {
		if e = migrateControl(ctx, tx); e != nil {
			return e
		}
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.persistent_deployments SET revision=$3,config_hash=$4,protocol=$5,schema_version=$6 WHERE environment=$1 AND deployment_id=$2 AND revision=$7 AND config_hash=$8 AND profile_hash=$9`, next.Environment, next.ID, next.Revision, next.ConfigHash, next.Protocol, next.SchemaVersion, old.Revision, old.ConfigHash, old.ProfileHash)
	if e != nil {
		return e
	}
	if e = oneResult(result); e != nil {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.runtime_cluster SET configuration_hash=$1,generation=generation+1 WHERE singleton`, next.ConfigHash); e != nil {
		return e
	}
	if e = appendAudit(ctx, tx, Audit{trace, trace, "offline-operator", "deployment_upgrade", next.ID, "activated"}); e != nil {
		return e
	}
	return tx.Commit()
}
