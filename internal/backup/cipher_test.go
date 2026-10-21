package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedBackupRejectsTamperTruncationAndWrongKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	raw := bytes.Repeat([]byte("private database material"), 90000)
	var out bytes.Buffer
	if e := encrypt(&out, bytes.NewReader(raw), key); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(out.Bytes(), []byte("private database material")) {
		t.Fatal("备份明文泄露")
	}
	var plain bytes.Buffer
	if e := decrypt(&plain, bytes.NewReader(out.Bytes()), key); e != nil || !bytes.Equal(plain.Bytes(), raw) {
		t.Fatal("无法还原", e)
	}
	for _, broken := range [][]byte{out.Bytes()[:len(out.Bytes())-1], out.Bytes()[:len(out.Bytes())-20], append(append([]byte{}, out.Bytes()...), 0), func() []byte { b := append([]byte{}, out.Bytes()...); b[len(b)/2] ^= 1; return b }()} {
		if e := decrypt(io.Discard, bytes.NewReader(broken), key); e == nil {
			t.Fatal("损坏备份被接受")
		}
	}
	other := make([]byte, 32)
	rand.Read(other)
	if e := decrypt(io.Discard, bytes.NewReader(out.Bytes()), other); e == nil {
		t.Fatal("错误密钥被接受")
	}
	var second bytes.Buffer
	encrypt(&second, bytes.NewReader(raw), key)
	if bytes.Equal(second.Bytes(), out.Bytes()) {
		t.Fatal("文件密钥或nonce复用")
	}
}
func TestPGCredentialsNeverEnterArgumentsAndOptionsAreExplicit(t *testing.T) {
	env, name, e := pgEnv("postgres://operator:private-secret@localhost:5432/keygate?sslmode=disable")
	if e != nil || name != "keygate" {
		t.Fatal(e)
	}
	found := false
	for _, v := range env {
		if v == "PGPASSWORD=private-secret" {
			found = true
		}
	}
	if !found {
		t.Fatal("未安全传递密码")
	}
	for _, bad := range []string{"https://localhost/x", "postgres://user@localhost/db?options=-cunsafe", "postgres://user@localhost/host=evil", "postgres://user@localhost/db?sslmode=disable&sslmode=require"} {
		if _, _, e = pgEnv(bad); e == nil {
			t.Fatal("非法连接选项被接受")
		}
	}
}

func TestBackupParentSyncFailureDoesNotPublishWitness(t *testing.T) {
	directory := t.TempDir()
	checkpoints := t.TempDir()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	r := &Runner{cfg: Config{Directory: directory, CheckpointDirectory: checkpoints}, sign: key}
	called := false
	_, e = r.publishCompletedBackup(Record{ID: "candidate"}, func(path string) error { called = path == directory; return errors.New("模拟目录同步失败") })
	if e == nil || !called {
		t.Fatal("父目录同步失败仍成功")
	}
	if _, e = os.Stat(filepath.Join(checkpoints, "latest.signed")); !os.IsNotExist(e) {
		t.Fatal("未持久化备份推进见证")
	}
}

func TestPublicVerificationKeyCannotBeBackupEncryptionKey(t *testing.T) {
	parent := t.TempDir()
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(parent, "public-key")
	os.WriteFile(file, pub, 0600)
	c := Config{Environment: "domain", Directory: t.TempDir(), CheckpointDirectory: t.TempDir(), PublicKeyFile: file, EncryptionKeyFile: file, PGDump: "unused", PGRestore: "unused", PSQL: "unused", BackupSeconds: 60, CheckpointSeconds: 10}
	if r, e := Open(context.Background(), c, false); e == nil {
		r.Close()
		t.Fatal("公开验签材料被用作备份加密密钥")
	}
}
