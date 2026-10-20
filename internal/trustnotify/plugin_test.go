package trustnotify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"ex-keygate/internal/pluginmock"
	"ex-keygate/internal/storage"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReminderMTLSRetryPayloadAndTarget(t *testing.T) {
	serverCert, ca, client, key, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	bodies := [][]byte{}
	code := http.StatusNoContent
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Idempotency-Key") != "stable-id" {
			t.Error("缺少mTLS或幂等键")
		}
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		w.WriteHeader(code)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	cfg := Config{URL: server.URL + "/notify", AllowedIPs: []string{"127.0.0.1"}, CAFile: filepath.Join(dir, "ca.pem"), CertificateFile: filepath.Join(dir, "client.pem"), KeyFile: filepath.Join(dir, "client.key")}
	for p, raw := range map[string][]byte{cfg.CAFile: ca, cfg.CertificateFile: client, cfg.KeyFile: key} {
		if e = os.WriteFile(p, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	plugin, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer plugin.Close()
	v := storage.TrustReminder{ID: "stable-id", Kind: "service", ServiceID: "orders-api", Fingerprint: "public-fingerprint", ExpiresAt: time.Now().UTC(), Severity: "due_1h", Attempts: 1, State: "sending"}
	if e = plugin.SendTrustReminder(context.Background(), v); e != nil {
		t.Fatal(e)
	}
	v.Attempts = 2
	v.State = "pending"
	if e = plugin.SendTrustReminder(context.Background(), v); e != nil {
		t.Fatal(e)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || bytes.Contains(bodies[0], []byte("attempts")) {
		t.Fatal("重试载荷变化")
	}

	approval := storage.ApprovalNotification{ID: "stable-id", RequestID: "approval-1", RecipientID: "approver-1", Kind: "approval_turn", Digest: "public-digest", ExpiresAt: v.ExpiresAt, CreatedAt: v.ExpiresAt}
	if e = plugin.SendApprovalNotification(context.Background(), approval); e != nil {
		t.Fatal(e)
	}
	approval.Attempts = 2
	if e = plugin.SendApprovalNotification(context.Background(), approval); e != nil {
		t.Fatal(e)
	}
	if len(bodies) != 4 || !bytes.Equal(bodies[2], bodies[3]) || !bytes.Contains(bodies[2], []byte("/manage#approvals")) {
		t.Fatal("审批提醒重试契约")
	}
	for _, forbidden := range []string{"attempts", "manifest", "password", "token", "email", "phone"} {
		if bytes.Contains(bodies[2], []byte(forbidden)) {
			t.Fatal("通知泄露额外字段")
		}
	}
	code = 202
	if e = plugin.SendApprovalNotification(context.Background(), approval); e == nil {
		t.Fatal("未确认审批提醒仍记成功")
	}
	code = 202
	if e = plugin.SendTrustReminder(context.Background(), v); e == nil {
		t.Fatal("异步未确认投递仍记成功")
	}
	code = 307
	if e = plugin.SendTrustReminder(context.Background(), v); e == nil {
		t.Fatal("接受重定向")
	}
	for _, bad := range []Config{{URL: "http://localhost"}, func() Config { c := cfg; c.AllowedIPs = []string{"127.0.0.2"}; return c }(), func() Config { c := cfg; c.URL += "?redirect=secret"; return c }()} {
		if p, e := New(bad); e == nil {
			p.Close()
			t.Fatal("非法端点配置被接受")
		}
	}
	if e = os.Chmod(cfg.KeyFile, 0644); e != nil {
		t.Fatal(e)
	}
	if p, e := New(cfg); e == nil {
		p.Close()
		t.Fatal("公开可读私钥被接受")
	}
}
