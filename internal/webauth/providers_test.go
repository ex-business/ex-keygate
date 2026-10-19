package webauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"ex-keygate/internal/pluginmock"
	"ex-keygate/internal/storage"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mockPluginFile(t *testing.T) string {
	t.Helper()
	mock, e := pluginmock.New()
	if e != nil {
		t.Fatal(e)
	}
	cert, ca, client, key, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	server := httptest.NewUnstartedServer(mock.Handler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	dir := t.TempDir()
	payload, proof := mock.Vector()
	cfg := pluginFile{DevelopmentOnly: true, Descriptor: pluginmock.Descriptor(), Endpoint: server.URL, AllowedIPs: []string{"127.0.0.1"}, CAFile: filepath.Join(dir, "ca"), ClientCertFile: filepath.Join(dir, "cert"), ClientKeyFile: filepath.Join(dir, "key"), Payload: payload, Proof: proof}
	for path, raw := range map[string][]byte{cfg.CAFile: ca, cfg.ClientCertFile: client, cfg.ClientKeyFile: key} {
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "connection.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return path
}
func TestPluginManagementApprovalAndDiagnostics(t *testing.T) {
	a := setupFlowPlugin(t, true, mockPluginFile(t))
	owner := a.loginAs(t, "demo-requester")
	voters := []businessActor{a.loginAs(t, "demo-approver-1"), a.loginAs(t, "demo-approver-2")}
	status, raw := a.business(t, owner, "GET", "/api/providers", nil)
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	for _, secret := range []string{"https://", "BEGIN", "clientKeyFile", "caFile"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("插件列表泄露连接或凭据", secret)
		}
	}
	var entries []pluginView
	if e := json.Unmarshal(raw, &entries); e != nil {
		t.Fatal(e)
	}
	var remote, hardware pluginView
	for _, v := range entries {
		if v.Policy.ID == "third-party-demo" {
			remote = v
		}
		if v.Policy.ID == "hardware-reserved" {
			hardware = v
		}
	}
	if remote.Policy.Enabled || remote.InstalledDigest == "" || hardware.Executor != "reserved" {
		t.Fatal("初始装配状态不正确", string(raw))
	}
	status, _ = a.business(t, owner, "POST", "/api/providers/third-party-demo/check", struct{}{})
	if status != 403 {
		t.Fatal("未批准插件运行自检", status)
	}
	op := storage.ControlOperation{Kind: storage.EnableProvider, ClientID: "provider-management", ExpectedRevision: remote.Policy.Revision, ProviderID: remote.Policy.ID, ProviderDigest: remote.InstalledDigest}
	request := a.submitOperation(t, owner, op)
	a.approveHTTP(t, voters, request)
	a.executeHTTP(t, owner, request)
	status, raw = a.business(t, owner, "POST", "/api/providers/third-party-demo/check", struct{}{})
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	var check storage.ProviderCheck
	if json.Unmarshal(raw, &check) != nil || check.State != "ready" || !check.Conformance {
		t.Fatal("mTLS公开向量自检失败", string(raw))
	}
	status, _ = a.business(t, voters[0], "POST", "/api/providers/third-party-demo/check", struct{}{})
	if status != 403 {
		t.Fatal("审批人越权自检", status)
	}
	status, _ = a.business(t, businessActor{cookie: owner.cookie}, "POST", "/api/providers/third-party-demo/disable", struct{}{})
	if status != 403 {
		t.Fatal("缺失CSRF仍停用", status)
	}
	status, raw = a.business(t, owner, "POST", "/api/providers/third-party-demo/disable", struct{}{})
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	status, _ = a.business(t, owner, "POST", "/api/providers/third-party-demo/check", struct{}{})
	if status != 403 {
		t.Fatal("停用后仍调用远端", status)
	}
	op.ProviderID = hardware.Policy.ID
	op.ProviderDigest = hardware.InstalledDigest
	op.ExpectedRevision = hardware.Policy.Revision
	status, _ = a.business(t, owner, "POST", "/api/requests", op)
	if status == 201 {
		t.Fatal("硬件预留项可启用")
	}
	if e := a.service.ConfigureDevelopmentPlugins(context.Background(), ""); e == nil {
		t.Fatal("监听后可替换装配")
	}
}
