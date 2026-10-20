package mfa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"ex-keygate/internal/pluginmock"
	"ex-keygate/provider"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"
)

func tlsPlugin(t *testing.T, handler http.Handler) *HTTPSPlugin {
	t.Helper()
	serverCert, ca, client, key, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	certificate, e := tls.X509KeyPair(client, key)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	plugin, e := NewHTTPSPlugin(server.URL, roots, certificate, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(plugin.Close)
	return plugin
}
func TestHTTPSPluginBoundContract(t *testing.T) {
	plugin := tlsPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		var result any
		switch r.URL.Path {
		case "/deliver":
			var d Delivery
			json.Unmarshal(raw, &d)
			result = map[string]any{"id": d.ID, "accepted": true}
		case "/hardware/begin":
			var c HardwareChallenge
			json.Unmarshal(raw, &c)
			result = map[string]any{"id": c.ID, "options": map[string]any{"publicKey": map[string]string{"challenge": c.Nonce}}}
		case "/hardware/verify":
			var c struct {
				Challenge HardwareChallenge `json:"challenge"`
			}
			json.Unmarshal(raw, &c)
			result = map[string]any{"id": c.Challenge.ID, "verified": true}
		}
		json.NewEncoder(w).Encode(map[string]any{"requestDigest": provider.Hash(raw), "result": result})
	}))
	if e := plugin.Send(context.Background(), Delivery{ID: "one", Method: Email, Destination: "one@example.invalid", Code: "12345678", ExpiresAt: time.Now().Add(time.Minute)}); e != nil {
		t.Fatal(e)
	}
	c := HardwareChallenge{ID: "key-one", Nonce: "nonce", Credential: "credential", Principal: "person", Origin: "https://console.example", ExpiresAt: time.Now().Add(time.Minute)}
	if _, e := plugin.Begin(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	if e := plugin.Verify(context.Background(), c, json.RawMessage(`{"assertion":"signed"}`)); e != nil {
		t.Fatal(e)
	}
}
func TestHTTPSPluginRejectsAmbiguousAndReplayedResults(t *testing.T) {
	for _, result := range []string{`{"id":"one","accepted":true,"accepted":false}`, `{"ID":"one","accepted":true}`, `{"id":"one","accepted":true,"extra":true}`, `{"id":"\\ud800","accepted":true}`} {
		t.Run(result, func(t *testing.T) {
			plugin := tlsPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"requestDigest":"`+provider.Hash(raw)+`","result":`+result+`}`)
			}))
			if e := plugin.Send(context.Background(), Delivery{ID: "one"}); e == nil {
				t.Fatal("歧义响应被接受")
			}
		})
	}
	plugin := tlsPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"requestDigest":"wrong","result":{"id":"one","accepted":true}}`)
	}))
	if e := plugin.Send(context.Background(), Delivery{ID: "one"}); e == nil {
		t.Fatal("错误摘要被接受")
	}
	redirect := tlsPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://127.0.0.1:1/deliver", 307) }))
	if e := redirect.Send(context.Background(), Delivery{ID: "one"}); e == nil {
		t.Fatal("插件跟随重定向")
	}
}

func TestClientCertificateChangesPluginTrustDigest(t *testing.T) {
	_, ca, certificate, key, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	dir := t.TempDir()
	caPath, certPath, keyPath := dir+"/ca.pem", dir+"/client.pem", dir+"/client-key.pem"
	for path, raw := range map[string][]byte{caPath: ca, certPath: certificate, keyPath: key} {
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	config := PluginConfig{Email: &PluginFiles{Endpoint: "https://localhost:9443", AllowedIPs: []string{"127.0.0.1"}, CAFile: caPath, CertificateFile: certPath, PrivateKeyFile: keyPath}}
	raw, _ := json.Marshal(config)
	_, first, closeFirst, e := LoadPlugins(raw)
	if e != nil {
		t.Fatal(e)
	}
	closeFirst()
	_, _, nextCert, nextKey, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(nextKey)
	if e = os.WriteFile(certPath, nextCert, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, nextKey, 0600); e != nil {
		t.Fatal(e)
	}
	_, second, closeSecond, e := LoadPlugins(raw)
	if e != nil {
		t.Fatal(e)
	}
	closeSecond()
	if first == second {
		t.Fatal("更换客户端身份未改变信任配置摘要")
	}
}

func TestHardwareRegistrationRequiresBoundTrustedCredential(t *testing.T) {
	for _, verified := range []bool{true, false} {
		plugin := tlsPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			var result any
			switch r.URL.Path {
			case "/hardware/register/begin":
				result = map[string]any{"id": "enrollment", "options": map[string]any{"publicKey": map[string]string{"challenge": "nonce"}}}
			case "/hardware/register/verify":
				result = map[string]any{"id": "enrollment", "verified": verified, "credential": "trusted-credential"}
			default:
				t.Error("注册调用了旧登录协议")
			}
			json.NewEncoder(w).Encode(map[string]any{"requestDigest": provider.Hash(raw), "result": result})
		}))
		challenge := HardwareChallenge{ID: "enrollment", Nonce: "nonce", Principal: "person", Origin: "https://console.example", ExpiresAt: time.Now().Add(time.Minute)}
		if _, e := plugin.RegisterBegin(context.Background(), challenge); e != nil {
			t.Fatal(e)
		}
		credential, e := plugin.RegisterVerify(context.Background(), challenge, json.RawMessage(`{"attestation":"proof"}`))
		if verified && (e != nil || credential != "trusted-credential") {
			t.Fatal("可信注册失败", e)
		}
		if !verified && (e == nil || credential != "") {
			t.Fatal("未验证注册被接受")
		}
	}
}
