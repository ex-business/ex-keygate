// Package mocksso is an intentionally unauthenticated, loopback-only development IdP.
// Its identities and simulated ACR must never be trusted by a production system.
package mocksso

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const ClientID = "keygate-console-dev"
const SimulatedACR = "urn:keygate:dev:simulated-mfa"

var ErrConfig = errors.New("mock SSO requires development/test and loopback HTTPS URLs")

type Config struct{ Environment, Issuer, RedirectURI string }
type grant struct {
	subject, nonce, challenge, redirect string
	expires                             time.Time
	authenticated                       time.Time
}
type Server struct {
	config Config
	key    *ecdsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]grant
	now    func() time.Time
}

func loopbackHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}
func New(c Config) (*Server, error) {
	issuer, err := url.Parse(c.Issuer)
	if err != nil || (c.Environment != "development" && c.Environment != "test") || !loopbackHTTPS(c.Issuer) || !loopbackHTTPS(c.RedirectURI) || issuer.Path != "" {
		return nil, ErrConfig
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Server{config: c, key: key, codes: map[string]grant{}, now: time.Now}, nil
}
func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func randomValue(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		// Refuse alternate Host routing to reduce localhost DNS-rebinding exposure.
		issuer, _ := url.Parse(s.config.Issuer)
		if r.Host != issuer.Host {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func output(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	output(w, map[string]any{"issuer": s.config.Issuer, "authorization_endpoint": s.config.Issuer + "/authorize", "token_endpoint": s.config.Issuer + "/token", "jwks_uri": s.config.Issuer + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"ES256"}, "token_endpoint_auth_methods_supported": []string{"none"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"openid", "profile"}, "acr_values_supported": []string{SimulatedACR}})
}
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	output(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: "dev-key", Algorithm: "ES256", Use: "sig"}}})
}
func (s *Server) authorization(values url.Values) bool {
	for _, v := range values {
		if len(v) != 1 {
			return false
		}
	}
	scope := strings.Fields(values.Get("scope"))
	openid := false
	for _, v := range scope {
		if v == "openid" {
			openid = true
		} else if v != "profile" {
			return false
		}
	}
	return values.Get("client_id") == ClientID && values.Get("redirect_uri") == s.config.RedirectURI && values.Get("response_type") == "code" && openid && values.Get("code_challenge_method") == "S256" && randomValue(values.Get("code_challenge")) && randomValue(values.Get("nonce")) && randomValue(values.Get("state")) && (values.Get("acr_values") == "" || values.Get("acr_values") == SimulatedACR)
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="zh"><meta charset="utf-8"><title>ExKeyGate 模拟 SSO</title><h1>仅供开发测试</h1><p>这里没有真实密码或多因素认证。身份和认证等级均为模拟数据，禁止生产使用。</p><form method="post" action="/authorize">{{range $name,$value := .}}<input type="hidden" name="{{$name}}" value="{{$value}}">{{end}}<label>测试身份 <select name="subject"><option value="demo-requester">测试申请人</option><option value="demo-approver-1">测试审批人一</option><option value="demo-approver-2">测试审批人二</option></select></label><button type="submit">模拟登录</button></form></html>`))

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > 16384 {
		http.Error(w, "invalid request", 400)
		return
	}
	if r.Method == http.MethodGet {
		if !s.authorization(r.URL.Query()) {
			http.Error(w, "invalid authorization request", 400)
			return
		}
		hidden := map[string]string{}
		for key := range r.URL.Query() {
			hidden[key] = r.URL.Query().Get(key)
		}
		// 浏览器表单需要保留 Origin；no-referrer 会让非CORS POST的Origin变为null。
		// 仅登录页使用origin级策略，不向后续请求泄露state等查询字段，仍严格校验POST来源。
		w.Header().Set("Referrer-Policy", "origin")
		// Chromium也校验表单提交后的重定向，只允许已配置的精确回调地址。
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self' "+s.config.RedirectURI+"; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginPage.Execute(w, hidden)
		return
	}
	if r.Header.Get("Origin") != s.config.Issuer || r.URL.RawQuery != "" {
		http.Error(w, "invalid origin", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if r.ParseForm() != nil || !s.authorization(r.PostForm) {
		http.Error(w, "invalid authorization request", 400)
		return
	}
	subject := r.PostForm.Get("subject")
	if subject != "demo-requester" && subject != "demo-approver-1" && subject != "demo-approver-2" {
		http.Error(w, "invalid test identity", 400)
		return
	}
	code := random()
	now := s.now()
	s.mu.Lock()
	// Bound process memory even though this mock has no production traffic role.
	for key, entry := range s.codes {
		if !now.Before(entry.expires) {
			delete(s.codes, key)
		}
	}
	if len(s.codes) >= 1024 {
		s.mu.Unlock()
		http.Error(w, "too many pending logins", 429)
		return
	}
	s.codes[code] = grant{subject, r.PostForm.Get("nonce"), r.PostForm.Get("code_challenge"), s.config.RedirectURI, now.Add(time.Minute), now}
	s.mu.Unlock()
	target, _ := url.Parse(s.config.RedirectURI)
	query := target.Query()
	query.Set("code", code)
	query.Set("state", r.PostForm.Get("state"))
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if r.URL.RawQuery != "" || r.ParseForm() != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			http.Error(w, "invalid request", 400)
			return
		}
	}
	if r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("client_id") != ClientID || !randomValue(r.PostForm.Get("code_verifier")) {
		http.Error(w, "invalid grant", 400)
		return
	}
	digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	now := s.now()
	s.mu.Lock()
	entry, ok := s.codes[r.PostForm.Get("code")]
	if !ok || !now.Before(entry.expires) || entry.redirect != r.PostForm.Get("redirect_uri") || subtle.ConstantTimeCompare([]byte(challenge), []byte(entry.challenge)) != 1 {
		s.mu.Unlock()
		http.Error(w, "invalid grant", 400)
		return
	}
	// Consume before signing; even signing failure cannot make a code reusable.
	delete(s.codes, r.PostForm.Get("code"))
	s.mu.Unlock()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: s.key, KeyID: "dev-key"}}, nil)
	if err != nil {
		http.Error(w, "token unavailable", 503)
		return
	}
	access := random()
	accessDigest := sha256.Sum256([]byte(access))
	payload, err := json.Marshal(map[string]any{"iss": s.config.Issuer, "sub": entry.subject, "aud": ClientID, "azp": ClientID, "iat": now.Unix(), "exp": now.Add(4 * time.Minute).Unix(), "auth_time": entry.authenticated.Unix(), "nonce": entry.nonce, "acr": SimulatedACR, "amr": []string{"mock"}, "at_hash": base64.RawURLEncoding.EncodeToString(accessDigest[:16])})
	if err != nil {
		http.Error(w, "token unavailable", 503)
		return
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		http.Error(w, "token unavailable", 503)
		return
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		http.Error(w, "token unavailable", 503)
		return
	}
	// The access token has no resource server and grants no ExKeyGate permissions.
	output(w, map[string]any{"id_token": compact, "access_token": access, "token_type": "Bearer", "expires_in": 240, "scope": "openid profile"})
}
