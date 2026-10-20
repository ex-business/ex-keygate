package main

import (
	"crypto/ed25519"
	"encoding/json"
	"ex-keygate/trustchain"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineToolsAndClientState(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	runtime := filepath.Join(base, "runtime")
	server := filepath.Join(base, "server")
	client := filepath.Join(base, "client")
	recovery := filepath.Join(base, "recovery")
	operations := []options{{action: "root-init", directory: root, output: filepath.Join(base, "root-result.json")}, {action: "recovery-init", directory: recovery}, {action: "status-init", directory: runtime, authority: root, environment: "app-test", hours: 24}, {action: "key-init", directory: server}, {action: "issue", directory: server, authority: root, environment: "app-test", service: "api-server", version: 1, hours: 24}, {action: "proposal", directory: server, rootFile: filepath.Join(root, "root.pem"), environment: "app-test", service: "api-server", version: 1, output: filepath.Join(base, "proposal.json")}, {action: "pin-init", directory: client, rootFile: filepath.Join(root, "root.pem"), recoveryPublic: filepath.Join(recovery, "recovery-public.json"), environment: "app-test", service: "api-server", audience: "desktop-app"}}
	for _, o := range operations {
		if e := execute(o); e != nil {
			t.Fatal(o.action, e)
		}
	}

	for _, item := range []struct{ action, dir, kind, service string }{{"renewal-proposal", server, "trust_certificate_renew", "api-server"}, {"status-proposal", runtime, "trust_status_update", "trust-status"}} {
		target := filepath.Join(base, item.action+".json")
		if e := execute(options{action: item.action, directory: item.dir, rootFile: filepath.Join(root, "root.pem"), environment: "app-test", service: "api-server", version: 1, revision: 1, output: target}); e != nil {
			t.Fatal(e)
		}
		raw, _ := os.ReadFile(target)
		var v map[string]any
		if json.Unmarshal(raw, &v) != nil || v["kind"] != item.kind || v["clientId"] != item.service || v["expectedRevision"] != "1" {
			t.Fatal("续期或状态提案错误")
		}
	}
	var proposal map[string]any
	b, _ := os.ReadFile(filepath.Join(base, "proposal.json"))
	if json.Unmarshal(b, &proposal) != nil || proposal["kind"] != "trust_certificate_publish" {
		t.Fatal("公开提案无效")
	}
	if _, e := os.Lstat(filepath.Join(runtime, "root.key")); !os.IsNotExist(e) {
		t.Fatal("运行目录出现根私钥")
	}
	s, e := trustchain.OpenClient(client)
	if e != nil {
		t.Fatal(e)
	}
	n, e := s.Challenge(time.Now())
	s.Close()
	if e != nil {
		t.Fatal(e)
	}
	payload := filepath.Join(base, "payload")
	os.WriteFile(payload, []byte("hello"), 0600)
	signed := filepath.Join(base, "message.json")
	if e = execute(options{action: "sign", directory: server, rootFile: filepath.Join(root, "root.pem"), environment: "app-test", service: "api-server", version: 1, audience: "desktop-app", nonce: n, payload: payload, output: signed}); e != nil {
		t.Fatal(e)
	}
	var m trustchain.Message
	if e = readJSON(signed, &m); e != nil {
		t.Fatal(e)
	}
	rootDER, _ := trustchain.ReadCertificate(filepath.Join(root, "root.pem"))
	statusDER, _ := trustchain.ReadCertificate(filepath.Join(runtime, "status.pem"))
	statusKey, _ := trustchain.ReadPrivateKey(filepath.Join(runtime, "status.key"))
	status, e := trustchain.SignStatus(rootDER, statusDER, statusKey, trustchain.Status{Environment: "app-test", ServiceID: "api-server", Revision: 1, Version: 1, CertificateHash: trustchain.Fingerprint(m.Certificate), Nonce: n, Audience: "desktop-app"}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	s, e = trustchain.OpenClient(client)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Verify(m, status, n, []byte("hello"), time.Now()); e != nil {
		t.Fatal(e)
	}
	s.Close()
	// 证书与私钥重复初始化不覆盖；宽权限私钥拒绝加载。
	before, _ := os.ReadFile(filepath.Join(server, "service.key"))
	if e = execute(options{action: "key-init", directory: server}); e == nil {
		t.Fatal("重复创建覆盖私钥")
	}
	after, _ := os.ReadFile(filepath.Join(server, "service.key"))
	if string(before) != string(after) {
		t.Fatal("私钥已变化")
	}
	os.Chmod(filepath.Join(server, "service.key"), 0644)
	if _, e = trustchain.ReadPrivateKey(filepath.Join(server, "service.key")); e == nil {
		t.Fatal("宽权限私钥被读取")
	}
	if _, ok := statusKey.Public().(ed25519.PublicKey); !ok {
		t.Fatal("算法错误")
	}
}
