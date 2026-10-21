package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPersistentDeploymentRestartAndControlledUpgrade(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	defer f.db.Exec(`DELETE FROM keygate.runtime_nodes; UPDATE keygate.runtime_cluster SET enabled=false,cluster_id='',configuration_hash='',generation=generation+1`)
	d := PersistentDeployment{Environment: f.c.environment, ID: unique(t), Revision: 1, ConfigHash: strings.Repeat("a", 64), ProfileHash: f.profile, Protocol: RuntimeProtocol, SchemaVersion: RuntimeSchemaVersion}
	if e := CheckRuntimeSchema(ctx, f.db); e != nil {
		t.Fatal(e)
	}
	if e := f.c.store.RegisterPersistentDeploymentOffline(ctx, d, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := f.c.store.RegisterPersistentDeploymentOffline(ctx, d, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("重复初始化", e)
	}
	node, e := f.c.store.AcquireNode(ctx, d.ID, d.ConfigHash, "restart-node", unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.store.AcquireNode(ctx, d.ID, d.ConfigHash, "restart-node", unique(t)); !errors.Is(e, ErrFenced) {
		t.Fatal("同节点双实例", e)
	}
	if _, e = f.c.store.AcquireNode(ctx, d.ID, strings.Repeat("f", 64), "wrong-config", unique(t)); !errors.Is(e, ErrFenced) {
		t.Fatal("异配置加入", e)
	}
	next := d
	next.Revision++
	next.ConfigHash = strings.Repeat("b", 64)
	cp, e := f.c.store.CaptureSafetyCheckpoint(ctx, d.Environment)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.store.UpgradePersistentDeploymentOffline(ctx, d, next, cp, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("未停服升级", e)
	}
	if e = node.DrainNode(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
	restarted, e := f.c.store.AcquireNode(ctx, d.ID, d.ConfigHash, "restart-node", unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = node.CheckReadiness(ctx); !errors.Is(e, ErrFenced) {
		t.Fatal("旧实例复活", e)
	}
	if e = restarted.DrainNode(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
	// 第一次检查点已因摘流和重启改变；不能拿旧快照升级。
	if e = f.c.store.UpgradePersistentDeploymentOffline(ctx, d, next, cp, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("过期检查点升级", e)
	}
	cp, e = f.c.store.CaptureSafetyCheckpoint(ctx, d.Environment)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.store.UpgradePersistentDeploymentOffline(ctx, d, next, cp, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.store.AcquireNode(ctx, d.ID, d.ConfigHash, "stale-release", unique(t)); !errors.Is(e, ErrFenced) {
		t.Fatal("旧发布重新加入", e)
	}
	fresh, e := f.c.store.AcquireNode(ctx, d.ID, next.ConfigHash, "new-release", unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = fresh.CheckReadiness(ctx); e != nil {
		t.Fatal(e)
	}
	actual, e := f.c.store.PersistentDeployment(ctx, d.Environment)
	if e != nil || actual.Revision != 2 || actual.ProfileHash != f.profile {
		t.Fatal("升级改写域身份", e)
	}
	if e = fresh.DrainNode(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
}

func TestPersistentSchemaRejectsUnknownFutureVersion(t *testing.T) {
	_, db := database(t)
	ctx := context.Background()
	if _, e := db.Exec(`INSERT INTO keygate.schema_migrations(version,checksum) VALUES(999,'future')`); e != nil {
		t.Fatal(e)
	}
	defer db.Exec(`DELETE FROM keygate.schema_migrations WHERE version=999`)
	if e := CheckRuntimeSchema(ctx, db); !errors.Is(e, ErrConflict) {
		t.Fatal("旧版本接受未来schema", e)
	}
}

func TestPersistentSchema21ControlledUpgrade(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	defer f.db.Exec(`DELETE FROM keygate.runtime_nodes; UPDATE keygate.runtime_cluster SET enabled=false,cluster_id='',configuration_hash='',generation=generation+1`)
	d := PersistentDeployment{Environment: f.c.environment, ID: unique(t), Revision: 1, ConfigHash: strings.Repeat("c", 64), ProfileHash: f.profile, Protocol: RuntimeProtocol, SchemaVersion: RuntimeSchemaVersion}
	if e := f.c.store.RegisterPersistentDeploymentOffline(ctx, d, unique(t)); e != nil {
		t.Fatal(e)
	}
	// 仅一次性测试库回建真实21结构，验证新DDL不会在普通启动或失败升级时提前落地。
	if _, e := f.db.Exec(`DROP TABLE keygate.approval_delivery_records; DROP TABLE keygate.approval_notification_alerts; DROP TABLE keygate.approval_notifications; ALTER TABLE keygate.control_requests DROP COLUMN withdrawn_by,DROP COLUMN withdrawal_reason,DROP COLUMN withdrawn_at,DROP COLUMN notice_terminal,DROP COLUMN notice_next_scan; DELETE FROM keygate.schema_migrations WHERE version>=22`); e != nil {
		t.Fatal(e)
	}
	defer func() {
		tx, e := f.db.BeginTx(ctx, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer tx.Rollback()
		if e = migrateControl(ctx, tx); e == nil {
			e = tx.Commit()
		}
		if e != nil {
			t.Error(e)
		}
	}()
	if _, e := f.db.Exec(`UPDATE keygate.persistent_deployments SET schema_version=21 WHERE environment=$1`, d.Environment); e != nil {
		t.Fatal(e)
	}
	d.SchemaVersion = 21
	if e := CheckRuntimeSchema(ctx, f.db); !errors.Is(e, ErrConflict) {
		t.Fatal("普通启动接受旧schema", e)
	}
	if e := CheckRuntimeSchemaVersion(ctx, f.db, 21); e != nil {
		t.Fatal(e)
	}
	cp, e := f.c.store.CaptureSafetyCheckpoint(ctx, d.Environment)
	if e != nil {
		t.Fatal(e)
	}
	next := d
	next.SchemaVersion = RuntimeSchemaVersion
	next.Revision = 2
	next.ConfigHash = strings.Repeat("d", 64)
	stale := d
	stale.Revision = 3
	if e = f.c.store.UpgradePersistentDeploymentOffline(ctx, stale, func() PersistentDeployment { v := next; v.Revision = 4; return v }(), cp, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("过期修订未拒绝", e)
	}
	if e = CheckRuntimeSchemaVersion(ctx, f.db, 21); e != nil {
		t.Fatal("失败升级未回滚DDL", e)
	}
	if e = f.c.store.UpgradePersistentDeploymentOffline(ctx, d, next, cp, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = CheckRuntimeSchema(ctx, f.db); e != nil {
		t.Fatal(e)
	}
	actual, e := f.c.store.PersistentDeployment(ctx, d.Environment)
	if e != nil || actual != next {
		t.Fatal("升级注册不一致", e)
	}
	if e = CheckRuntimeSchemaVersion(ctx, f.db, 21); !errors.Is(e, ErrConflict) {
		t.Fatal("旧版本接受新schema", e)
	}
}

func TestPersistentSchema22ControlledUpgrade(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	defer f.db.Exec(`DELETE FROM keygate.runtime_nodes; UPDATE keygate.runtime_cluster SET enabled=false,cluster_id='',configuration_hash='',generation=generation+1`)
	d := PersistentDeployment{Environment: f.c.environment, ID: unique(t), Revision: 1, ConfigHash: strings.Repeat("c", 64), ProfileHash: f.profile, Protocol: RuntimeProtocol, SchemaVersion: RuntimeSchemaVersion}
	if e := f.c.store.RegisterPersistentDeploymentOffline(ctx, d, unique(t)); e != nil {
		t.Fatal(e)
	}
	// 仅一次性测试库回建真实22结构，验证新DDL不会在普通启动或失败升级时提前落地。
	if _, e := f.db.Exec(`DROP INDEX keygate.approval_notice_operations; DROP TABLE keygate.approval_delivery_records; DROP TABLE keygate.approval_notification_alerts; ALTER TABLE keygate.approval_notifications DROP COLUMN resend_count,DROP COLUMN last_resend_at; DELETE FROM keygate.schema_migrations WHERE version>=23`); e != nil {
		t.Fatal(e)
	}
	defer func() {
		tx, e := f.db.BeginTx(ctx, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer tx.Rollback()
		if e = migrateControl(ctx, tx); e == nil {
			e = tx.Commit()
		}
		if e != nil {
			t.Error(e)
		}
	}()
	if _, e := f.db.Exec(`UPDATE keygate.persistent_deployments SET schema_version=22 WHERE environment=$1`, d.Environment); e != nil {
		t.Fatal(e)
	}
	d.SchemaVersion = 22
	if e := CheckRuntimeSchema(ctx, f.db); !errors.Is(e, ErrConflict) {
		t.Fatal("普通启动接受旧schema", e)
	}
	if e := CheckRuntimeSchemaVersion(ctx, f.db, 22); e != nil {
		t.Fatal(e)
	}
	cp, e := f.c.store.CaptureSafetyCheckpoint(ctx, d.Environment)
	if e != nil {
		t.Fatal(e)
	}
	next := d
	next.SchemaVersion = RuntimeSchemaVersion
	next.Revision = 2
	next.ConfigHash = strings.Repeat("d", 64)
	stale := d
	stale.Revision = 3
	if e = f.c.store.UpgradePersistentDeploymentOffline(ctx, stale, func() PersistentDeployment { v := next; v.Revision = 4; return v }(), cp, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("过期修订未拒绝", e)
	}
	if e = CheckRuntimeSchemaVersion(ctx, f.db, 22); e != nil {
		t.Fatal("失败升级未回滚DDL", e)
	}
	if e = f.c.store.UpgradePersistentDeploymentOffline(ctx, d, next, cp, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = CheckRuntimeSchema(ctx, f.db); e != nil {
		t.Fatal(e)
	}
	actual, e := f.c.store.PersistentDeployment(ctx, d.Environment)
	if e != nil || actual != next {
		t.Fatal("升级注册不一致", e)
	}
	if e = CheckRuntimeSchemaVersion(ctx, f.db, 22); !errors.Is(e, ErrConflict) {
		t.Fatal("旧版本接受新schema", e)
	}
}
