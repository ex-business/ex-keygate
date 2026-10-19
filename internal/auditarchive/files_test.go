package auditarchive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedArchiveRetryAndTamper(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sink := Files{dir, key}
	raw := []byte(`{"eventId":"event-1","environment":"test"}`)
	for range 2 {
		if _, e = sink.Put(context.Background(), "event-1", raw); e != nil {
			t.Fatal(e)
		}
	}
	before, e := VerifyInventory(dir, "test", pub, nil)
	if e != nil || before.Count != 1 {
		t.Fatal(before, e)
	}
	if _, e = sink.Put(context.Background(), "event-1", []byte(`{"eventId":"event-1","environment":"test","changed":true}`)); e == nil {
		t.Fatal("覆盖原归档")
	}
	if e = os.WriteFile(filepath.Join(dir, "event-1.json"), []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyInventory(dir, "test", pub, nil); e == nil {
		t.Fatal("无效签名接受")
	}
	if e = os.Remove(filepath.Join(dir, "event-1.json")); e != nil {
		t.Fatal(e)
	}
	after, e := VerifyInventory(dir, "test", pub, nil)
	if e != nil || after == before {
		t.Fatal("独立清单未发现删除", e)
	}
}
func TestArchiveRejectsSymlinkAndPublicDirectory(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sink := Files{dir, key}
	target := filepath.Join(t.TempDir(), "target")
	if e := os.WriteFile(target, []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, filepath.Join(dir, "event-1.json")); e != nil {
		t.Fatal(e)
	}
	if _, e := sink.Put(context.Background(), "event-1", []byte(`{"eventId":"event-1"}`)); e == nil {
		t.Fatal("接受符号链接")
	}
	if _, e := VerifyInventory(dir, "test", pub, nil); e == nil {
		t.Fatal("扫描接受符号链接")
	}
	_ = os.Remove(filepath.Join(dir, "event-1.json"))
	_ = os.Chmod(dir, 0755)
	if _, e := sink.Put(context.Background(), "event-1", []byte(`{"eventId":"event-1"}`)); e == nil {
		t.Fatal("公开目录接受秘密操作")
	}
}

func TestPrivateReaderRejectsOversizeAndPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if e := os.WriteFile(p, make([]byte, 65), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPrivate(p, 64); e == nil {
		t.Fatal("超长私钥接受")
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPrivate(p, 100); e == nil {
		t.Fatal("公开文件接受")
	}
}

func TestIndependentSignatureRejectsWrongTrustAndTamper(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	raw := []byte(`{"kind":"keygate-state-v1"}`)
	signed, e := json.Marshal(Signed{raw, ed25519.Sign(key, raw)})
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "checkpoint")
	if e = WriteOnce(path, signed); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifySignedFile(path, pub); e != nil {
		t.Fatal(e)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, e = VerifySignedFile(path, other); e == nil {
		t.Fatal("信任文件自报公钥")
	}
	signed[len(signed)-3] ^= 1
	_ = os.WriteFile(path, signed, 0600)
	if _, e = VerifySignedFile(path, pub); e == nil {
		t.Fatal("校验点篡改接受")
	}
}
