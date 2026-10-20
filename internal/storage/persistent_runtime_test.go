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
