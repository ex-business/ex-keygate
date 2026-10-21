package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"ex-keygate/internal/auditarchive"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type backupCLIResult struct{ ID, CheckpointFile, CheckpointSHA256, BackupID string }

// TestBackupRestoreDrill 仅由独立临时单域库脚本启用，真正执行pg_dump/pg_restore与恢复后HMAC认证，不接触演示库。
func TestBackupRestoreDrill(t *testing.T) {
	cli := os.Getenv("KEYGATE_BACKUP_CLI")
	if cli == "" {
		t.Skip("需scripts/test-backup.py的独立临时库")
	}
	f := newKeyFixture(t)
	ctx := context.Background()
	issued := f.issue(t, 1)
	bundle, secret := f.claim(t, issued)
	defer clear(secret)
	mac := hmac.New(sha256.New, secret)
	mac.Write(bundle.PossessionInput)
	if e := f.k.ConfirmPossession(ctx, issued.ID, mac.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	f.operation(t, ActivateKey, 1, "")
	body := []byte(`{"probe":true}`)
	request, _ := signedProbe(t, f, secret, body)
	if e := f.k.AuthenticateProbe(ctx, request, body, "keygate-probe"); e != nil {
		t.Fatal("演练前密钥未能认证", e)
	}
	parent := t.TempDir()
	backupDir := filepath.Join(parent, "backups")
	checkpoints := filepath.Join(parent, "independent-checkpoints")
	os.Mkdir(backupDir, 0700)
	os.Mkdir(checkpoints, 0700)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	enc := make([]byte, 32)
	rand.Read(enc)
	defer clear(enc)
	files := map[string][]byte{"sign.key": key, "public.key": pub, "encryption.key": enc, "database": []byte(os.Getenv("KEYGATE_TEST_DATABASE_URL"))}
	for name, raw := range files {
		if e = os.WriteFile(filepath.Join(parent, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	cfg := map[string]any{"environment": f.f.c.environment, "databaseFile": filepath.Join(parent, "database"), "directory": backupDir, "checkpointDirectory": checkpoints, "signingKeyFile": filepath.Join(parent, "sign.key"), "publicKeyFile": filepath.Join(parent, "public.key"), "encryptionKeyFile": filepath.Join(parent, "encryption.key"), "pgDump": os.Getenv("KEYGATE_BACKUP_PG_DUMP"), "pgRestore": os.Getenv("KEYGATE_BACKUP_PG_RESTORE"), "psql": os.Getenv("KEYGATE_BACKUP_PSQL"), "backupSeconds": 60, "checkpointSeconds": 10}
	raw, _ := json.Marshal(cfg)
	config := filepath.Join(parent, "config.json")
	os.WriteFile(config, raw, 0600)
	run := func(action string, args ...string) (backupCLIResult, error) {
		cmd := exec.Command(cli, append([]string{"-config", config, "-action", action}, args...)...)
		out, e := cmd.Output()
		if e != nil {
			return backupCLIResult{}, e
		}
		var result backupCLIResult
		if json.Unmarshal(out, &result) != nil {
			return result, ErrInvalid
		}
		return result, nil
	}
	// 在快照已捕获、pg_dump尚未导入时并发撤销，导出仍必须与撤销前检查点完全一致。
	gate := filepath.Join(parent, "snapshot-gate")
	os.Mkdir(gate, 0700)
	t.Setenv("KEYGATE_BACKUP_DRILL_GATE", gate)
	type backupOutcome struct {
		v backupCLIResult
		e error
	}
	ready := make(chan backupOutcome, 1)
	go func() { v, e := run("backup"); ready <- backupOutcome{v, e} }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, e = os.Stat(filepath.Join(gate, "snapshot-ready")); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pg_dump快照同步超时")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e = f.f.c.Revoke(ctx, f.f.tokens[0], RevocationInput{IncidentID: unique(t), ClientID: "one", KeyVersion: 1, Reason: "confirmed_leak"}, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(gate, "continue"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	outcome := <-ready
	old := outcome.v
	if outcome.e != nil {
		t.Fatal("并发撤销时备份失败", outcome.e)
	}
	t.Setenv("KEYGATE_BACKUP_DRILL_GATE", "")
	latest, e := run("checkpoint")
	if e != nil {
		t.Fatal("独立最新检查点失败", e)
	}
	source, _ := url.Parse(os.Getenv("KEYGATE_TEST_DATABASE_URL"))
	targetName := "keygate_restore_" + unique(t)
	if !identifier.MatchString(targetName) {
		t.Fatal("非法演练库名")
	}
	if _, e = f.f.db.Exec(`CREATE DATABASE ` + targetName); e != nil {
		t.Fatal(e)
	}
	defer f.f.db.Exec(`DROP DATABASE ` + targetName + ` WITH (FORCE)`)
	targetURL := *source
	targetURL.Path = "/" + targetName
	targetFile := filepath.Join(parent, "target-database")
	os.WriteFile(targetFile, []byte(targetURL.String()), 0600)
	args := func(b backupCLIResult, w backupCLIResult) []string {
		return []string{"-backup-id", b.BackupID, "-latest-checkpoint", w.CheckpointFile, "-expected-checkpoint-sha256", w.CheckpointSHA256, "-target-database-file", targetFile, "-confirm-empty-target", targetName}
	}
	if _, e = run("restore", args(old, latest)...); e == nil {
		t.Fatal("撤销前旧备份绕过最新独立检查点")
	}
	targetDB, e := sql.Open("pgx", targetURL.String())
	if e != nil {
		t.Fatal(e)
	}
	defer targetDB.Close()
	var untouched bool
	if e = targetDB.QueryRow(`SELECT NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='keygate')`).Scan(&untouched); e != nil || !untouched {
		t.Fatal("旧备份被拒绝前修改目标", e)
	}
	current, e := run("backup")
	if e != nil {
		t.Fatal("撤销后新备份失败", e)
	}
	// 可信签名的故障注入清单与真实dump不匹配：必须在同一还原事务中失败，目标仍为空。
	manifestFile := filepath.Join(backupDir, current.BackupID, "manifest.signed")
	originalManifest, e := os.ReadFile(manifestFile)
	if e != nil {
		t.Fatal(e)
	}
	var envelope auditarchive.Signed
	if json.Unmarshal(originalManifest, &envelope) != nil {
		t.Fatal("清单无效")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(envelope.Payload, &fields) != nil {
		t.Fatal("载荷无效")
	}
	var altered SafetyCheckpoint
	if json.Unmarshal(fields["state"], &altered) != nil {
		t.Fatal("检查点无效")
	}
	table := altered.Tables["clients"]
	table.Count++
	altered.Tables["clients"] = table
	fields["state"], _ = json.Marshal(altered)
	envelope.Payload, _ = json.Marshal(fields)
	envelope.Signature = ed25519.Sign(key, envelope.Payload)
	brokenManifest, _ := json.Marshal(envelope)
	os.WriteFile(manifestFile, brokenManifest, 0600)
	brokenCheckpoint := filepath.Join(checkpoints, "fault-injected.signed")
	os.WriteFile(brokenCheckpoint, brokenManifest, 0600)
	brokenWitness := current
	brokenWitness.CheckpointFile = brokenCheckpoint
	brokenWitness.CheckpointSHA256 = digestBytes(brokenManifest)
	if _, e = run("restore", args(current, brokenWitness)...); e == nil {
		t.Fatal("清单与还原表不一致仍提交")
	}
	if e = targetDB.QueryRow(`SELECT NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='keygate')`).Scan(&untouched); e != nil || !untouched {
		t.Fatal("核对失败留下未隔离恢复状态", e)
	}
	os.WriteFile(manifestFile, originalManifest, 0600)
	dumpFile := filepath.Join(backupDir, current.BackupID, "database.kgb")
	encrypted, e := os.ReadFile(dumpFile)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(encrypted), "root_budgets") {
		t.Fatal("数据库明文出现在备份")
	}
	originalCipher := append([]byte{}, encrypted...)
	encrypted[len(encrypted)/2] ^= 1
	os.WriteFile(dumpFile, encrypted, 0600)
	if _, e = run("restore", args(current, current)...); e == nil {
		t.Fatal("损坏备份被还原")
	}
	if e = targetDB.QueryRow(`SELECT NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='keygate')`).Scan(&untouched); e != nil || !untouched {
		t.Fatal("损坏备份修改目标", e)
	}
	os.WriteFile(dumpFile, originalCipher, 0600)
	if _, e = run("restore", args(current, current)...); e != nil {
		t.Fatal("新备份恢复隔离失败", e)
	}
	targetStore, _ := New(targetDB)
	restoredControl := *f.f.c
	restoredControl.store = targetStore
	restoredKeys := *f.k
	restoredKeys.control = &restoredControl
	if e = restoredControl.CheckQuarantinedOffline(ctx); e != nil {
		t.Fatal("恢复未隔离", e)
	}
	request, _ = signedProbe(t, f, secret, body)
	if e = restoredKeys.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
		t.Fatal("恢复后接受已撤销密钥")
	}
	// 故障注入仅重开测试库中的外层开关，证明旧版本终态仍阻止认证，不依赖客户端禁用这一层。
	if _, e = targetDB.Exec(`UPDATE keygate.clients SET state='enabled'; UPDATE keygate.client_roots SET enabled=true`); e != nil {
		t.Fatal(e)
	}
	request, _ = signedProbe(t, f, secret, body)
	if e = restoredKeys.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
		t.Fatal("旧密钥借客户端重启复活")
	}
	if _, e = targetDB.Exec(`UPDATE keygate.key_versions SET state='active'`); e == nil {
		t.Fatal("撤销终态被覆盖")
	}
	if _, e = run("restore", args(current, current)...); e == nil {
		t.Fatal("覆盖非空库")
	}
	// 即使操作者错误地固定旧见证，恢复也只隔离并永久废弃旧版本；不将其标记为业务恢复完成。
	oldTarget := "keygate_restore_" + unique(t)
	if _, e = f.f.db.Exec(`CREATE DATABASE ` + oldTarget); e != nil {
		t.Fatal(e)
	}
	defer f.f.db.Exec(`DROP DATABASE ` + oldTarget + ` WITH (FORCE)`)
	oldURL := *source
	oldURL.Path = "/" + oldTarget
	oldFile := filepath.Join(parent, "old-target")
	os.WriteFile(oldFile, []byte(oldURL.String()), 0600)
	oldArgs := args(old, old)
	for i := range oldArgs {
		if oldArgs[i] == targetFile {
			oldArgs[i] = oldFile
		}
		if oldArgs[i] == targetName {
			oldArgs[i] = oldTarget
		}
	}
	if _, e = run("restore", oldArgs...); e != nil {
		t.Fatal("旧备份隔离演练失败", e)
	}
	oldDB, e := sql.Open("pgx", oldURL.String())
	if e != nil {
		t.Fatal(e)
	}
	defer oldDB.Close()
	oldStore, _ := New(oldDB)
	restoredControl.store = oldStore
	if _, e = oldDB.Exec(`UPDATE keygate.clients SET state='enabled'; UPDATE keygate.client_roots SET enabled=true`); e != nil {
		t.Fatal(e)
	}
	request, _ = signedProbe(t, f, secret, body)
	if e = restoredKeys.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
		t.Fatal("旧快照丢失撤销记录后仍接受旧密钥")
	}
	t.Log("恢复演练通过：撤销前旧备份被最新见证拒绝；新备份恢复隔离；重开外层开关仍拒绝旧密钥；旧见证恢复也永久作废旧版本")
}
