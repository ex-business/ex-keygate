package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"ex-keygate/internal/auditarchive"
	"ex-keygate/internal/deployment"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/storage"
	"ex-keygate/internal/webauth"
	"ex-keygate/provider"
)

type persistentRuntime struct {
	action, node       string
	files              *deployment.Files
	index              deployment.Index
	revision           deployment.Revision
	previous           storage.PersistentDeployment
	checkpoint, pubkey string
	snapshotCleanup    func()
}

func randomRuntimeID(prefix string) string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic("安全随机源不可用")
	}
	return prefix + hex.EncodeToString(b)
}
func absoluteSetting(s deployment.Settings) (deployment.Settings, error) {
	values := []*string{&s.DatabaseFile, &s.SSOFile, &s.SSOSecretFile, &s.TLSDirectory, &s.PluginFile, &s.MFAPluginsFile, &s.ReminderFile, &s.Output, &s.ApprovalNotifyFile}
	for _, p := range values {
		if *p != "" {
			v, e := filepath.Abs(*p)
			if e != nil {
				return s, e
			}
			*p = v
		}
	}
	if s.TrustDirectory != "" {
		paths := strings.Split(s.TrustDirectory, ",")
		for i, p := range paths {
			v, e := filepath.Abs(strings.TrimSpace(p))
			if e != nil {
				return s, e
			}
			paths[i] = v
		}
		s.TrustDirectory = strings.Join(paths, ",")
	}
	if s.Port < 1 || s.Port > 65535 || s.Output == "" {
		return s, deployment.ErrState
	}
	return s, nil
}
func preparePersistent(ctx context.Context, action, dir, key, node, nextConfig, checkpoint, pubkey string, settings deployment.Settings) (*persistentRuntime, deployment.Settings, error) {
	if dir == "" {
		if action != "" || key != "" || nextConfig != "" || checkpoint != "" || pubkey != "" {
			return nil, settings, deployment.ErrState
		}
		return nil, settings, nil
	}
	if action != "init" && action != "run" && action != "plan" && action != "upgrade" {
		return nil, settings, errors.New("持久模式必须显式选择init、run、plan或upgrade")
	}
	files, e := deployment.Open(dir, key, action == "init")
	if e != nil {
		return nil, settings, e
	}
	rt := &persistentRuntime{action: action, node: node, files: files, checkpoint: checkpoint, pubkey: pubkey}
	success := false
	defer func() {
		if !success {
			files.Close()
		}
	}()
	binary, e := deployment.BinaryDigest()
	if e != nil {
		return nil, settings, e
	}
	if action == "init" {
		settings, e = absoluteSetting(settings)
		if e != nil {
			return nil, settings, e
		}
		deps, e := deployment.Dependencies(settings)
		if e != nil {
			return nil, settings, e
		}
		pinned, e := auditarchive.ReadPrivate(pubkey, 32)
		if e != nil || len(pinned) != 32 {
			return nil, settings, errors.New("首次初始化必须固定独立升级检查点公钥")
		}
		login, e := keycrypto.Generate()
		if e != nil {
			return nil, settings, e
		}
		rt.index = deployment.Index{UpgradePublicKey: pinned, Format: "keygate-deployment-v1", Environment: randomRuntimeID("persistent-"), ID: randomRuntimeID("deployment-"), LoginRootID: randomRuntimeID("login-root-"), InitialRootID: randomRuntimeID("client-root-"), LoginKey: login, DatabaseFile: settings.DatabaseFile}
		rt.revision = deployment.Revision{Number: 1, Protocol: storage.RuntimeProtocol, Schema: storage.RuntimeSchemaVersion, Binary: binary, Settings: settings, Dependencies: deps}
		if e = files.WriteIndex(rt.index); e != nil {
			return nil, settings, e
		}
		if e = files.WriteRevision(rt.revision); e != nil {
			return nil, settings, e
		}
	} else {
		rt.index, e = files.ReadIndex()
		if e != nil {
			return nil, settings, e
		}
		raw, e := readPrivate(rt.index.DatabaseFile)
		if e != nil {
			return nil, settings, e
		}
		dsn := strings.TrimSpace(string(raw))
		clear(raw)
		if !developmentDatabase(dsn) {
			return nil, settings, deployment.ErrState
		}
		db, e := sql.Open("pgx", dsn)
		if e != nil {
			return nil, settings, deployment.ErrState
		}
		defer db.Close()
		schemaVersion := storage.RuntimeSchemaVersion
		if action == "plan" || action == "upgrade" {
			if e = db.QueryRowContext(ctx, `SELECT schema_version FROM keygate.persistent_deployments WHERE environment=$1`, rt.index.Environment).Scan(&schemaVersion); e != nil {
				return nil, settings, deployment.ErrState
			}
		}
		if e = storage.CheckRuntimeSchemaVersion(ctx, db, schemaVersion); e != nil {
			return nil, settings, errors.New("持久部署数据库版本不兼容，需受控迁移后再启动")
		}
		store, _ := storage.New(db)
		rt.previous, e = store.PersistentDeployment(ctx, rt.index.Environment)
		if e != nil {
			return nil, settings, errors.New("持久管理域不存在或初始化未完成，禁止重建")
		}
		rt.revision, e = files.ReadRevision(rt.previous.Revision, rt.previous.ConfigHash)
		if e != nil {
			return nil, settings, e
		}
		if rt.previous.ID != rt.index.ID || rt.previous.ConfigHash != rt.revision.Digest() || rt.previous.Protocol != storage.RuntimeProtocol || rt.previous.SchemaVersion != schemaVersion || rt.revision.Protocol != storage.RuntimeProtocol || rt.revision.Schema != schemaVersion || rt.revision.Settings.DatabaseFile != rt.index.DatabaseFile {
			return nil, settings, deployment.ErrState
		}
		if action == "run" {
			if binary != rt.revision.Binary || nextConfig != "" || checkpoint != "" || pubkey != "" {
				return nil, settings, errors.New("二进制或配置不匹配，请先生成受控升级计划")
			}
			if e = deployment.VerifyDependencies(rt.revision); e != nil {
				return nil, settings, e
			}
		} else {
			next := rt.revision
			next.Number++
			next.Schema = storage.RuntimeSchemaVersion
			next.Binary = binary
			if nextConfig != "" {
				raw, e := readPrivate(nextConfig)
				if e != nil {
					return nil, settings, e
				}
				if provider.DecodeStrict(raw, &next.Settings) != nil {
					return nil, settings, deployment.ErrState
				}
				next.Settings, e = absoluteSetting(next.Settings)
				if e != nil {
					return nil, settings, e
				}
			}
			if next.Settings.DatabaseFile != rt.index.DatabaseFile {
				return nil, settings, errors.New("升级不允许隐式切换权威数据库")
			}
			next.Dependencies, e = deployment.Dependencies(next.Settings)
			if e != nil {
				return nil, settings, e
			}
			rt.revision = next
		}
		settings = rt.revision.Settings
	}
	snapshotSettings, cleanup, e := files.Snapshot(rt.revision)
	if e != nil {
		return nil, settings, e
	}
	rt.snapshotCleanup = cleanup
	success = true
	return rt, snapshotSettings, nil
}
func (rt *persistentRuntime) close() {
	clear(rt.index.LoginKey)
	if rt.snapshotCleanup != nil {
		rt.snapshotCleanup()
	}
	rt.files.Close()
}
func (rt *persistentRuntime) store(ctx context.Context, s *storage.Store) (*storage.Store, error) {
	if rt.action != "run" {
		return s, nil
	}
	return s.AcquireNode(ctx, rt.index.ID, rt.revision.Digest(), rt.node, randomRuntimeID("runtime-join-"))
}
func (rt *persistentRuntime) attach(ctx context.Context, s *webauth.Service, store *storage.Store) error {
	if rt.action == "init" {
		material, e := keycrypto.Generate()
		if e != nil {
			return e
		}
		defer clear(material)
		return s.InitializePersistentSimulatedFlow(ctx, rt.index.Environment, rt.index.InitialRootID, material, rt.files.WriteRoot)
	}
	if rt.action != "run" {
		return nil
	}
	if s.PersistentProfileDigest() != rt.previous.ProfileHash {
		return errors.New("持久管理域的身份配置不匹配")
	}
	c, e := storage.NewDevelopmentControl("development", rt.index.Environment, s.PersistentProfileDigest(), store)
	if e != nil {
		return e
	}
	ids, e := c.RequiredRootIDs(ctx)
	if e != nil {
		return e
	}
	roots := []webauth.DevelopmentRoot{}
	defer func() {
		for _, r := range roots {
			clear(r.Material)
		}
	}()
	for _, id := range ids {
		material, e := rt.files.ReadRoot(id)
		if e != nil {
			return e
		}
		roots = append(roots, webauth.DevelopmentRoot{ID: id, Material: material})
	}
	if e = s.AttachSimulatedNode(ctx, rt.index.Environment, roots); e != nil {
		return e
	}
	return s.SetPersistentRootWriter(rt.files.WriteRoot, rt.files.LoadOrCreateRoot)
}
func (rt *persistentRuntime) register(ctx context.Context, s *webauth.Service, store *storage.Store) error {
	return store.RegisterPersistentDeploymentOffline(ctx, storage.PersistentDeployment{Environment: rt.index.Environment, ID: rt.index.ID, Revision: 1, ConfigHash: rt.revision.Digest(), ProfileHash: s.PersistentProfileDigest(), Protocol: storage.RuntimeProtocol, SchemaVersion: storage.RuntimeSchemaVersion}, randomRuntimeID("runtime-init-"))
}
func (rt *persistentRuntime) upgrade(ctx context.Context, s *webauth.Service, store *storage.Store) error {
	if s.PersistentProfileDigest() != rt.previous.ProfileHash {
		return errors.New("本次升级不允许更换身份源、MFA策略信任或登录保护根，请使用独立治理流程")
	}
	next := rt.previous
	next.Revision = rt.revision.Number
	next.ConfigHash = rt.revision.Digest()
	next.Protocol = storage.RuntimeProtocol
	next.SchemaVersion = storage.RuntimeSchemaVersion
	if rt.action == "plan" {
		raw, _ := json.Marshal(map[string]any{"action": "upgrade_plan", "deployment": next.ID, "fromRevision": rt.previous.Revision, "toRevision": next.Revision, "fromConfig": rt.previous.ConfigHash, "toConfig": next.ConfigHash, "schema": next.SchemaVersion, "protocol": next.Protocol, "requiresStoppedNodes": true, "requiresSignedCheckpoint": true})
		fmt.Println(string(raw))
		return nil
	}
	pub := rt.index.UpgradePublicKey
	if rt.pubkey != "" {
		provided, e := auditarchive.ReadPrivate(rt.pubkey, 32)
		if e != nil || !bytes.Equal(provided, pub) {
			return errors.New("升级公钥与初始化固定身份不一致")
		}
	}
	var e error
	raw, e := auditarchive.VerifySignedFile(rt.checkpoint, ed25519.PublicKey(pub))
	if e != nil {
		return errors.New("升级检查点签名无效")
	}
	var cp storage.SafetyCheckpoint
	if decodeUpgradeCheckpoint(raw, &cp) != nil || cp.Environment != rt.index.Environment {
		return errors.New("升级检查点与管理域不一致")
	}
	// 修订先独占落盘，权威库随后选择它；提交结果不明时run从数据库读取实际生效修订，绝不回退猜测。
	if e = rt.files.WriteRevision(rt.revision); e != nil {
		return e
	}
	if e = store.UpgradePersistentDeploymentOffline(ctx, rt.previous, next, cp, randomRuntimeID("runtime-upgrade-")); e != nil {
		return e
	}
	slog.InfoContext(ctx, "持久部署升级已激活，旧节点配置已隔离", "environment", next.Environment, "deployment_id", next.ID, "revision", next.Revision, "result", "activated")
	return nil
}

// guardPersistentInitialization 防止误把已有临时演示库变为专用持久集群；会话锁覆盖整个首次初始化。
func guardPersistentInitialization(ctx context.Context, db *sql.DB) (func(), error) {
	conn, e := db.Conn(ctx)
	if e != nil {
		return nil, e
	}
	var acquired bool
	if e = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(610847123)`).Scan(&acquired); e != nil || !acquired {
		conn.Close()
		return nil, deployment.ErrState
	}
	release := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(610847123)`)
		conn.Close()
	}
	var exists bool
	if e = conn.QueryRowContext(ctx, `SELECT to_regclass('keygate.security_domains') IS NOT NULL`).Scan(&exists); e != nil {
		release()
		return nil, e
	}
	if exists {
		var count int
		if e = conn.QueryRowContext(ctx, `SELECT count(*) FROM keygate.security_domains`).Scan(&count); e != nil || count != 0 {
			release()
			return nil, errors.New("持久初始化必须使用专用空数据库，禁止接管已有管理域")
		}
	}
	return release, nil
}

// decodeUpgradeCheckpoint 接受运维工具生成的规范JSON，拒绝重复/未知字段；时间类型沿用标准库，不误按普通结构体解码。
func decodeUpgradeCheckpoint(raw []byte, out *storage.SafetyCheckpoint) error {
	if e := json.Unmarshal(raw, out); e != nil {
		return e
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, canonical) {
		return deployment.ErrState
	}
	return nil
}
