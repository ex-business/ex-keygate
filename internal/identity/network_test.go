package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

func trustedClient(server *httptest.Server) *http.Client {
	client := oidcHTTPClient()
	transport := client.Transport.(boundedTransport).base.(*http.Transport)
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	transport.TLSClientConfig.RootCAs.AddCert(server.Certificate())
	return client
}
func TestJWKSTransportPolicies(t *testing.T) {
	var followed atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/followed", http.StatusFound)
		case "/followed":
			followed.Add(1)
		case "/large":
			_, _ = io.WriteString(w, strings.Repeat("x", 2<<20))
		case "/slow":
			<-r.Context().Done()
		}
	}))
	defer server.Close()
	client := trustedClient(server)
	defer client.CloseIdleConnections()
	response, err := client.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || followed.Load() != 0 {
		t.Fatal("redirect followed")
	}
	response, err = client.Get(server.URL + "/large")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || len(body) != 1<<20 {
		t.Fatal("response size not bounded", len(body), err)
	}
	client.Timeout = 30 * time.Millisecond
	if response, err = client.Get(server.URL + "/slow"); err == nil {
		response.Body.Close()
		t.Fatal("timeout not enforced")
	}
}
func TestRejectOldTLSAndUntrustedCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	client := trustedClient(server)
	defer client.CloseIdleConnections()
	if response, err := client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("TLS 1.2 accepted")
	}
	modern := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer modern.Close()
	untrusted := oidcHTTPClient()
	defer untrusted.CloseIdleConnections()
	if response, err := untrusted.Get(modern.URL); err == nil {
		response.Body.Close()
		t.Fatal("untrusted certificate accepted")
	}
}
func TestRemoteJWKSRotationAndOversize(t *testing.T) {
	base, firstKey, claims, nonce := fixture(t)
	secondKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	current := firstKey
	oversize := false
	var fetches atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		mu.Lock()
		defer mu.Unlock()
		if oversize {
			_, _ = io.WriteString(w, `{"padding":"`+strings.Repeat("x", 2<<20)+`"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &current.PublicKey, Algorithm: "ES256", Use: "sig"}}})
	}))
	defer server.Close()
	client := trustedClient(server)
	defer client.CloseIdleConnections()
	config := base.config
	config.Issuer = server.URL
	config.JWKSURL = server.URL + "/keys"
	claims["iss"] = server.URL
	keyset := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), config.JWKSURL)
	verifier := newOIDC(config, keyset, base.now)
	if _, err = verifier.VerifyLogin(context.Background(), sign(t, firstKey, claims), nonce); err != nil {
		t.Fatal("first JWKS failed", err)
	}
	mu.Lock()
	current = secondKey
	mu.Unlock()
	if _, err = verifier.VerifyLogin(context.Background(), sign(t, secondKey, claims), nonce); err != nil {
		t.Fatal("rotated JWKS failed", err)
	}
	if fetches.Load() < 2 {
		t.Fatal("key rotation did not refresh")
	}
	mu.Lock()
	oversize = true
	mu.Unlock()
	emptyCache := newOIDC(config, oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), config.JWKSURL), base.now)
	if _, err = emptyCache.VerifyLogin(context.Background(), sign(t, secondKey, claims), nonce); err == nil {
		t.Fatal("oversize JWKS accepted")
	}
}
