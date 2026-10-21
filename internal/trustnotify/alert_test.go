package trustnotify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"ex-keygate/internal/alertmock"
	"ex-keygate/internal/pluginmock"
	"ex-keygate/internal/storage"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAlertMTLSAndStableRetry(t *testing.T) {
	cert, ca, client, key, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	server := httptest.NewUnstartedServer(alertmock.New(1).Handler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	cfg := Config{URL: server.URL + "/alerts", AllowedIPs: []string{"127.0.0.1"}, CAFile: filepath.Join(dir, "ca.pem"), CertificateFile: filepath.Join(dir, "client.pem"), KeyFile: filepath.Join(dir, "client.key")}
	for path, raw := range map[string][]byte{cfg.CAFile: ca, cfg.CertificateFile: client, cfg.KeyFile: key} {
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	p, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	for _, channel := range []string{"email", "sms", "webhook"} {
		v := storage.AlertMessage{ID: "stable-" + channel, IncidentID: "incident", EventID: "event", RouteID: "route", Channel: channel, Target: "operations", Kind: "trigger", Code: "plugin_unavailable", ObservedAt: time.Now().UTC(), Attempts: 1, State: "sending"}
		if e = p.SendSystemAlert(context.Background(), v); e == nil {
			t.Fatal("第一次模拟失败仍成功")
		}
		v.Attempts = 2
		v.State = "pending"
		if e = p.SendSystemAlert(context.Background(), v); e != nil {
			t.Fatal("同ID重试载荷不稳定", e)
		}
		v.Target = "changed"
		if e = p.SendSystemAlert(context.Background(), v); e == nil {
			t.Fatal("同ID不同载荷被接收")
		}
	}
}
