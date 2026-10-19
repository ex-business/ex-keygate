package mocksso

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ex-keygate/internal/identity"
)

type fixture struct {
	s        *Server
	http     *httptest.Server
	client   *http.Client
	verifier *identity.OIDC
}

func setup(t *testing.T) fixture {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	issuer := "https://" + server.Listener.Addr().String()
	mock, err := New(Config{"test", issuer, issuer + "/callback"})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = mock.Handler()
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	verifier, err := identity.NewOIDC(identity.Config{Issuer: issuer, JWKSURL: issuer + "/jwks", ClientID: ClientID, AllowedACR: []string{SimulatedACR}, MaxAuthAge: 5 * time.Minute, TrustedRoots: roots, DevelopmentMode: true})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{mock, server, client, verifier}
}
func (f fixture) post(t *testing.T, path string, values url.Values, origin string) (int, []byte, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.http.URL+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	response, err := f.client.Do(req)
	if err != nil {
		t.Error(err)
		return 0, nil, ""
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}
	return response.StatusCode, body, response.Header.Get("Location")
}
func (f fixture) parameters(subject string) (url.Values, string) {
	verifier := random()
	hash := sha256.Sum256([]byte(verifier))
	return url.Values{"client_id": {ClientID}, "redirect_uri": {f.s.config.RedirectURI}, "response_type": {"code"}, "scope": {"openid profile"}, "state": {random()}, "nonce": {random()}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "subject": {subject}}, verifier
}
func tokenForm(f fixture, code, verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {ClientID}, "redirect_uri": {f.s.config.RedirectURI}, "code": {code}, "code_verifier": {verifier}}
}
func (f fixture) grant(t *testing.T, subject string) (string, string, string) {
	t.Helper()
	params, verifier := f.parameters(subject)
	status, body, location := f.post(t, "/authorize", params, f.s.config.Issuer)
	if status != 303 {
		t.Fatalf("authorize failed: %d %s", status, body)
	}
	target, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if target.Query().Get("state") != params.Get("state") {
		t.Fatal("state lost")
	}
	return target.Query().Get("code"), verifier, params.Get("nonce")
}
func TestAuthorizationCodePKCEAndIdentity(t *testing.T) {
	f := setup(t)
	seen := map[string]bool{}
	response, err := f.client.Get(f.http.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var discovery map[string]any
	if err = json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if discovery["issuer"] != f.http.URL || discovery["jwks_uri"] != f.http.URL+"/jwks" {
		t.Fatal("invalid discovery")
	}
	for _, subject := range []string{"demo-requester", "demo-approver-1", "demo-approver-2"} {
		code, verifier, nonce := f.grant(t, subject)
		status, body, _ := f.post(t, "/token", tokenForm(f, code, verifier), "")
		if status != 200 {
			t.Fatalf("token failed: %d", status)
		}
		var tokens struct {
			IDToken string `json:"id_token"`
		}
		if err = json.Unmarshal(body, &tokens); err != nil {
			t.Fatal(err)
		}
		principal, err := f.verifier.VerifyLogin(context.Background(), tokens.IDToken, nonce)
		if err != nil || seen[principal.ID] {
			t.Fatal("identity verification failed", err)
		}
		seen[principal.ID] = true
		if status, _, _ = f.post(t, "/token", tokenForm(f, code, verifier), ""); status != 400 {
			t.Fatal("code replay accepted")
		}
		if _, err = f.verifier.VerifyLogin(context.Background(), tokens.IDToken, random()); err == nil {
			t.Fatal("wrong login nonce accepted")
		}
	}
}
func TestRejectedAuthorizationAndPKCE(t *testing.T) {
	f := setup(t)
	cases := map[string]string{"redirect_uri": "https://attacker.invalid/callback", "client_id": "other", "code_challenge_method": "plain", "state": "short", "subject": "admin", "acr_values": "real-mfa"}
	for key, value := range cases {
		params, _ := f.parameters("demo-requester")
		params.Set(key, value)
		status, _, location := f.post(t, "/authorize", params, f.s.config.Issuer)
		if status == 303 || location != "" {
			t.Fatal("invalid authorization accepted", key)
		}
	}
	params, _ := f.parameters("demo-requester")
	if status, _, _ := f.post(t, "/authorize", params, "https://attacker.invalid"); status != 403 {
		t.Fatal("foreign origin accepted")
	}
	code, verifier, _ := f.grant(t, "demo-requester")
	if status, _, _ := f.post(t, "/token", tokenForm(f, code, random()), ""); status != 400 {
		t.Fatal("wrong PKCE accepted")
	}
	if status, _, _ := f.post(t, "/token", tokenForm(f, code, verifier), ""); status != 200 {
		t.Fatal("wrong proof consumed legitimate code")
	}
}
func TestConcurrentCodeConsumptionAndExpiry(t *testing.T) {
	f := setup(t)
	code, verifier, _ := f.grant(t, "demo-requester")
	var wg sync.WaitGroup
	var success atomic.Int64
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _, _ := f.post(t, "/token", tokenForm(f, code, verifier), "")
			if status == 200 {
				success.Add(1)
			} else if status != 400 {
				t.Error("unexpected status", status)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("code accepted more than once", success.Load())
	}
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	f.s.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	code, verifier, _ = f.grant(t, "demo-requester")
	clock.Add(61)
	if status, _, _ := f.post(t, "/token", tokenForm(f, code, verifier), ""); status != 400 {
		t.Fatal("expired code accepted")
	}
}
func TestMockProductionAndAddressBoundaries(t *testing.T) {
	for _, config := range []Config{{"production", "https://127.0.0.1:19443", "https://127.0.0.1/callback"}, {"development", "http://127.0.0.1:19443", "https://127.0.0.1/callback"}, {"test", "https://identity.example", "https://127.0.0.1/callback"}, {"test", "https://127.0.0.1:19443", "https://remote.example/callback"}} {
		if _, err := New(config); err == nil {
			t.Fatal("unsafe mock configuration accepted")
		}
	}
	if _, err := identity.NewOIDC(identity.Config{Issuer: "https://127.0.0.1:19443", JWKSURL: "https://127.0.0.1:19443/jwks", ClientID: ClientID, AllowedACR: []string{SimulatedACR}, MaxAuthAge: time.Minute}); err == nil {
		t.Fatal("mock ACR accepted outside development mode")
	}
}

func TestLoginPageBrowserSecurityPolicy(t *testing.T) {
	f := setup(t)
	params, _ := f.parameters("demo-requester")
	params.Del("subject")
	response, err := f.client.Get(f.http.URL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Referrer-Policy") != "origin" {
		t.Fatal("login page must preserve form Origin without query disclosure")
	}
	expected := "default-src 'none'; form-action 'self' " + f.s.config.RedirectURI + "; base-uri 'none'; frame-ancestors 'none'"
	if response.Header.Get("Content-Security-Policy") != expected {
		t.Fatal("form redirect must allow only configured callback")
	}
	if status, _, _ := f.post(t, "/authorize", params, "null"); status != 403 {
		t.Fatal("null Origin must remain denied")
	}
	response2, err := f.client.Get(f.http.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer response2.Body.Close()
	if response2.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("non-login policy changed")
	}
}
