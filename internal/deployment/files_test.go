package deployment

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedRootsRejectWrongKeyTamperAndOverwrite(t *testing.T) {
	parent := t.TempDir()
	key := make([]byte, 32)
	rand.Read(key)
	keyFile := filepath.Join(parent, "wrapping.key")
	if e := os.WriteFile(keyFile, key, 0600); e != nil {
		t.Fatal(e)
	}
	directory := filepath.Join(parent, "runtime")
	f, e := Open(directory, keyFile, true)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	secret := make([]byte, 32)
	rand.Read(secret)
	if e = f.WriteRoot("one", secret); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(directory, "root-one.sealed"))
	if e != nil || bytes.Contains(raw, secret) {
		t.Fatal("根秘密明文落盘", e)
	}
	value, e := f.ReadRoot("one")
	if e != nil || !bytes.Equal(value, secret) {
		t.Fatal("重启根解封失败", e)
	}
	clear(value)
	if e = f.WriteRoot("one", secret); e != nil {
		t.Fatal("相同材料幂等写入失败", e)
	}
	other := make([]byte, 32)
	rand.Read(other)
	if e = f.WriteRoot("one", other); e == nil {
		t.Fatal("同名根被覆盖")
	}
	if e = os.WriteFile(filepath.Join(parent, "wrong.key"), other, 0600); e != nil {
		t.Fatal(e)
	}
	wrong, e := Open(directory, filepath.Join(parent, "wrong.key"), false)
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if _, e = wrong.ReadRoot("one"); e == nil {
		t.Fatal("错误包装密钥仍打开根")
	}
	raw[len(raw)-1] ^= 1
	os.WriteFile(filepath.Join(directory, "root-one.sealed"), raw, 0600)
	if _, e = f.ReadRoot("one"); e == nil {
		t.Fatal("篡改密文仍打开根")
	}
	if _, e = Open(directory, keyFile, true); e == nil {
		t.Fatal("已有目录重新初始化")
	}
	if e = f.WriteRoot("../escape", secret); e == nil {
		t.Fatal("根名越界")
	}
}
func TestDeploymentFilesRejectSymlinksAndCoLocatedKey(t *testing.T) {
	parent := t.TempDir()
	key := filepath.Join(parent, "key")
	os.WriteFile(key, make([]byte, 32), 0600)
	d := filepath.Join(parent, "deployment")
	f, e := Open(d, key, true)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	inside := filepath.Join(d, "key")
	os.WriteFile(inside, make([]byte, 32), 0600)
	if _, e = Open(d, inside, false); e == nil {
		t.Fatal("包装密钥和密文混放")
	}
	if e = os.Symlink(key, filepath.Join(d, "root-one.sealed")); e != nil {
		t.Fatal(e)
	}
	if _, e = f.ReadRoot("one"); e == nil {
		t.Fatal("符号链接根被加载")
	}
	os.Chmod(key, 0644)
	if _, e = Open(d, key, false); e == nil {
		t.Fatal("公开包装密钥被接受")
	}
}

func TestKeyDirectoryBoundaryResolvesParentAliases(t *testing.T) {
	parent := t.TempDir()
	actual := filepath.Join(parent, "actual")
	os.Mkdir(actual, 0700)
	key := filepath.Join(actual, "wrapping.key")
	os.WriteFile(key, make([]byte, 32), 0600)
	alias := filepath.Join(parent, "alias")
	if e := os.Symlink(actual, alias); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(actual, filepath.Join(alias, "wrapping.key"), false); e == nil {
		t.Fatal("父目录别名绕过密钥隔离")
	}
}
func TestOrphanRootMaterialIsReused(t *testing.T) {
	parent := t.TempDir()
	key := filepath.Join(parent, "wrapping.key")
	os.WriteFile(key, make([]byte, 32), 0600)
	f, e := Open(filepath.Join(parent, "runtime"), key, true)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	first, e := f.LoadOrCreateRoot("approved-root")
	if e != nil {
		t.Fatal(e)
	}
	defer clear(first)
	retry, e := f.LoadOrCreateRoot("approved-root")
	if e != nil || !bytes.Equal(first, retry) {
		t.Fatal("失败事务重试替换了已落盘根", e)
	}
	clear(retry)
}
func TestSnapshotUsesVerifiedBytesAfterOriginalReplacement(t *testing.T) {
	parent := t.TempDir()
	key := filepath.Join(parent, "wrapping.key")
	os.WriteFile(key, make([]byte, 32), 0600)
	f, e := Open(filepath.Join(parent, "runtime"), key, true)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	tls := filepath.Join(parent, "tls")
	os.Mkdir(tls, 0700)
	for _, name := range []string{"cert.pem", "key.pem", "ca.pem"} {
		os.WriteFile(filepath.Join(tls, name), []byte("bound-material"), 0600)
	}
	database := filepath.Join(parent, "database")
	os.WriteFile(database, []byte("bound-database"), 0600)
	s := Settings{DatabaseFile: database, TLSDirectory: tls}
	deps, e := Dependencies(s)
	if e != nil {
		t.Fatal(e)
	}
	r := Revision{Number: 1, Settings: s, Dependencies: deps}
	snapshot, clean, e := f.Snapshot(r)
	if e != nil {
		t.Fatal(e)
	}
	defer clean()
	os.WriteFile(database, []byte("replaced-database"), 0600)
	os.WriteFile(filepath.Join(tls, "key.pem"), []byte("replaced-key"), 0600)
	raw, e := os.ReadFile(snapshot.DatabaseFile)
	if e != nil || string(raw) != "bound-database" {
		t.Fatal("装配重读原数据库文件", e)
	}
	raw, e = os.ReadFile(filepath.Join(snapshot.TLSDirectory, "key.pem"))
	if e != nil || string(raw) != "bound-material" {
		t.Fatal("装配重读原密钥文件", e)
	}
	if _, _, e = f.Snapshot(r); e == nil {
		t.Fatal("改动的原文件再次被接受")
	}
}

func TestRootPublicationDoesNotHideSyncFailure(t *testing.T) {
	parent := t.TempDir()
	key := filepath.Join(parent, "wrapping.key")
	os.WriteFile(key, make([]byte, 32), 0600)
	f, e := Open(filepath.Join(parent, "runtime"), key, true)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	f.syncDirectory = func(string) error { return os.ErrPermission }
	if raw, e := f.LoadOrCreateRoot("sync-failure"); e == nil || raw != nil {
		t.Fatal("同步失败仍交付根材料")
	}
	// 文件可读不等于已确认落盘，已有材料重试也必须继续拒绝。
	if raw, e := f.ReadRoot("sync-failure"); e != nil || len(raw) != 32 {
		t.Fatal("测试未覆盖链接成功后的同步失败", e)
	}
	if raw, e := f.LoadOrCreateRoot("sync-failure"); e == nil || raw != nil {
		t.Fatal("成功读取掩盖持久性失败")
	}
	f.syncDirectory = nil
	raw, e := f.LoadOrCreateRoot("sync-failure")
	if e != nil || len(raw) != 32 {
		t.Fatal("恢复同步后无法重用原材料", e)
	}
	clear(raw)
}

func TestSnapshotCannotHideOfflineRootKeyInSourceDirectory(t *testing.T) {
	parent := t.TempDir()
	tls := filepath.Join(parent, "tls")
	trust := filepath.Join(parent, "trust")
	os.Mkdir(tls, 0700)
	os.Mkdir(trust, 0700)
	for _, name := range []string{"cert.pem", "key.pem", "ca.pem"} {
		os.WriteFile(filepath.Join(tls, name), []byte("tls"), 0600)
	}
	for _, name := range []string{"root.pem", "status.pem", "status.key", "runtime.json", "root.key"} {
		os.WriteFile(filepath.Join(trust, name), []byte("material"), 0600)
	}
	if _, e := Dependencies(Settings{TLSDirectory: tls, TrustDirectory: trust}); e == nil {
		t.Fatal("快照掩盖了原目录中的离线根私钥")
	}
}
