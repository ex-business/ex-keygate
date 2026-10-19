package provider_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"ex-keygate/internal/pluginmock"
	"ex-keygate/provider"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func testAdapter(t *testing.T, handler http.Handler) (*provider.HTTPVerifier, *pluginmock.Service) {
	t.Helper()
	mock, e := pluginmock.New()
	if e != nil {
		t.Fatal(e)
	}
	if handler == nil {
		handler = mock.Handler()
	}
	cert, ca, client, key, e := pluginmock.DevelopmentTLS()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	clientCert, e := tls.X509KeyPair(client, key)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	adapter, e := provider.NewHTTPVerifier(provider.HTTPConfig{Descriptor: pluginmock.Descriptor(), Endpoint: server.URL, AllowedIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Roots: roots, Certificate: clientCert})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(adapter.Close)
	return adapter, mock
}
func TestMutualTLSPluginContract(t *testing.T) {
	p, mock := testAdapter(t, nil)
	ctx := context.Background()
	if e := p.CheckHealth(ctx); e != nil {
		t.Fatal(e)
	}
	payload, proof := mock.Vector()
	v := provider.Verification{Environment: "test", Audience: "plugin-diagnostic", Purpose: "conformance", RequestID: "request-1", ClientID: "plugin-diagnostic", Key: provider.KeyReference{ID: "mock-conformance", Version: 1}, Algorithm: "ed25519", Payload: payload, Proof: proof}
	if e := p.Verify(ctx, v); e != nil {
		t.Fatal(e)
	}
	v.Proof[0] ^= 1
	if e := p.Verify(ctx, v); !errors.Is(e, provider.ErrRejected) {
		t.Fatal("错误证明通过", e)
	}
	v.Purpose = ""
	if e := p.Verify(ctx, v); !errors.Is(e, provider.ErrInvalid) {
		t.Fatal("缺失上下文通过", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e := p.CheckHealth(canceled); !errors.Is(e, provider.ErrUnavailable) {
		t.Fatal("取消被忽略", e)
	}
}
func TestPluginRejectsAmbiguousResponsesAndRedirects(t *testing.T) {
	for _, body := range []string{`{"protocolVersion":"1","providerId":"third-party-demo","providerVersion":"1","ready":true,"ready":false}`, `{"protocolVersion":"1","providerId":"third-party-demo","providerVersion":"1","Ready":true}`, `{"protocolVersion":"1","providerId":"third-party-demo","providerVersion":"1","ready":true,"extra":true}`} {
		t.Run(body, func(t *testing.T) {
			p, _ := testAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			if e := p.CheckHealth(context.Background()); !errors.Is(e, provider.ErrUnavailable) {
				t.Fatal("歧义结果被接受", e)
			}
		})
	}
	p, _ := testAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1:1/v1/health", 307)
	}))
	if e := p.CheckHealth(context.Background()); !errors.Is(e, provider.ErrUnavailable) {
		t.Fatal("跟随重定向", e)
	}
}
func TestPluginResponseBindsRequestDigest(t *testing.T) {
	p, mock := testAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"protocolVersion":"1","providerId":"third-party-demo","providerVersion":"1","requestId":"request-1","requestDigest":"wrong","verified":true}`))
	}))
	payload, proof := mock.Vector()
	if e := p.Verify(context.Background(), provider.Verification{Environment: "test", Audience: "plugin-diagnostic", Purpose: "conformance", RequestID: "request-1", ClientID: "plugin-diagnostic", Key: provider.KeyReference{ID: "mock-conformance", Version: 1}, Algorithm: "ed25519", Payload: payload, Proof: proof}); !errors.Is(e, provider.ErrUnavailable) {
		t.Fatal("响应未绑定原请求", e)
	}
}
