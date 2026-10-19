// Package webauth implements a development OIDC browser-login boundary.
// Authenticated sessions never imply local management or approval permissions.
package webauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ex-keygate/internal/config"
	"ex-keygate/internal/identity"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/storage"
	"golang.org/x/oauth2"
)

const loginCookie = "__Host-keygate_login"
const sessionCookie = "__Host-keygate_session"

var ErrConfig = errors.New("invalid browser authentication configuration")

type Protector interface {
	RootID() string
	Seal(context.Context, keycrypto.Binding, []byte, string, string) (keycrypto.Envelope, error)
	Open(context.Context, keycrypto.Binding, keycrypto.Envelope) ([]byte, error)
}
type Config struct {
	MFAPlugins                                        mfa.Plugins `json:"-"`
	MFAPluginPolicyHash                               string
	BrowserReturnPaths                                map[string]string
	Environment                                       config.Environment
	Identity                                          identity.Config
	AuthorizationEndpoint, TokenEndpoint, CallbackURL string
	PolicyVersion                                     uint64
	TokenAuthMethod                                   string
	ClientSecret                                      string `json:"-"`
}
type Service struct {
	handlerStarted  atomic.Bool
	flow            *developmentFlow
	logger          *slog.Logger
	lastRejection   atomic.Int64
	suppressed      atomic.Uint64
	config          Config
	origin, profile string
	store           *storage.Store
	protector       Protector
	verifier        *identity.OIDC
	oauth           oauth2.Config
	client          *http.Client
}

func New(c Config, store *storage.Store, protector Protector) (*Service, error) {
	if (c.Environment != config.Development && c.Environment != config.Test) || store == nil || protector == nil || c.PolicyVersion == 0 {
		return nil, ErrConfig
	}
	c.BrowserReturnPaths = maps.Clone(c.BrowserReturnPaths)
	for id, path := range c.BrowserReturnPaths {
		if !browserReturnPath.MatchString(path) || len(path) > 256 || !browserClientID.MatchString(id) {
			return nil, ErrConfig
		}
	}
	c.Identity.AllowedACR = slices.Clone(c.Identity.AllowedACR)
	c.Identity.RequiredAMR = slices.Clone(c.Identity.RequiredAMR)
	if c.TokenAuthMethod == "" {
		c.TokenAuthMethod = "none"
	}
	if c.TokenAuthMethod != "none" && c.TokenAuthMethod != "client_secret_basic" && c.TokenAuthMethod != "client_secret_post" {
		return nil, ErrConfig
	}
	if (c.TokenAuthMethod == "none" && c.ClientSecret != "") || (c.TokenAuthMethod != "none" && (c.ClientSecret == "" || len(c.ClientSecret) > 4096 || strings.ContainsAny(c.ClientSecret, "\r\n"))) {
		return nil, ErrConfig
	}
	if c.Identity.TrustedRoots != nil {
		c.Identity.TrustedRoots = c.Identity.TrustedRoots.Clone()
	}
	verifier, err := identity.NewOIDC(c.Identity)
	if err != nil {
		return nil, err
	}
	issuer, _ := url.Parse(c.Identity.Issuer)
	for _, endpoint := range []string{c.AuthorizationEndpoint, c.TokenEndpoint} {
		u, err := url.Parse(endpoint)
		if err != nil || !safeURL(u) || u.Host != issuer.Host {
			return nil, ErrConfig
		}
	}
	callback, err := url.Parse(c.CallbackURL)
	if err != nil || !safeURL(callback) || callback.Path != "/auth/callback" {
		return nil, ErrConfig
	}
	// 身份摘要绑定根代次和受控策略；信任根等配置变化须同步提高全部节点的 PolicyVersion。
	// H5 返回路径也纳入摘要，避免不同节点把同一登录事务导向不同入口。
	if (c.MFAPlugins.Email != nil || c.MFAPlugins.SMS != nil || c.MFAPlugins.Hardware != nil) && !validMFAPolicyHash(c.MFAPluginPolicyHash) {
		return nil, ErrConfig
	}
	profileValues := []any{c.MFAPluginPolicyHash, "admin-fresh-login-v1", c.Identity.RequiredAMR, c.TokenAuthMethod, c.Identity.Issuer, c.Identity.JWKSURL, c.Identity.ClientID, c.Identity.AllowedACR, c.Identity.MaxAuthAge, c.AuthorizationEndpoint, c.TokenEndpoint, c.CallbackURL, c.PolicyVersion, c.Environment, protector.RootID()}
	if len(c.BrowserReturnPaths) > 0 {
		profileValues = append(profileValues, c.BrowserReturnPaths)
	}
	profileBytes, err := json.Marshal(profileValues)
	if err != nil {
		return nil, ErrConfig
	}
	digest := sha256.Sum256(profileBytes)
	s := &Service{logger: slog.Default(), config: c, origin: callback.Scheme + "://" + callback.Host, profile: hex.EncodeToString(digest[:]), store: store, protector: protector, verifier: verifier, client: identity.NewHTTPClient(c.Identity.TrustedRoots)}
	authStyle := oauth2.AuthStyleInParams
	if c.TokenAuthMethod == "client_secret_basic" {
		authStyle = oauth2.AuthStyleInHeader
	}
	s.oauth = oauth2.Config{ClientSecret: c.ClientSecret, ClientID: c.Identity.ClientID, RedirectURL: c.CallbackURL, Scopes: []string{"openid", "profile"}, Endpoint: oauth2.Endpoint{AuthURL: c.AuthorizationEndpoint, TokenURL: c.TokenEndpoint, AuthStyle: authStyle}}
	return s, nil
}
func safeURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}
func random() string {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}
func parse(raw string) ([32]byte, bool) {
	var out [32]byte
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return out, false
	}
	copy(out[:], decoded)
	return out, true
}
func hash(raw string) [32]byte { return sha256.Sum256([]byte(raw)) }
func audit(request, actor, action, target, result string) storage.Audit {
	return storage.Audit{EventID: "event-" + hexToken(), RequestID: request, ActorID: actor, Action: action, TargetID: target, Result: result}
}
func hexToken() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw[:])
}
func binding(environment config.Environment, stateHash [32]byte) keycrypto.Binding {
	return keycrypto.Binding{Environment: string(environment), ClientID: "keygate-console", KeyID: hex.EncodeToString(stateHash[:]), Version: 1, Purpose: "login_pkce"}
}
func cookie(r *http.Request, name string) (string, bool) {
	found := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			found = c.Value
			count++
		}
	}
	_, valid := parse(found)
	return found, count == 1 && valid
}
func setCookie(w http.ResponseWriter, name, value string, maxAge int, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: sameSite})
}
func csrf(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("keygate-session-csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func fail(w http.ResponseWriter, status int) { http.Error(w, http.StatusText(status), status) }
func (s *Service) Handler() http.Handler {
	s.handlerStarted.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) {
		businessJSON(w, 200, map[string]string{"status": "alive"})
	})
	mux.HandleFunc("GET /health/ready", s.readiness)
	if s.flow != nil {
		s.flowRoutes(mux)
	}
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("GET /auth/session", s.session)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if s.flow != nil {
			_, _ = w.Write([]byte(`<html lang="zh"><meta charset="utf-8"><title>ExKeyGate 开发流程</title><h1>ExKeyGate 开发流程</h1><p>已显式开启模拟授权；仅供开发测试。</p><a href="/auth/login">通过模拟 SSO 登录</a><p><a href="/manage">客户端与密钥管理</a></p></html>`))
			return
		}
		_, _ = w.Write([]byte(`<!doctype html><html lang="zh"><meta charset="utf-8"><title>ExKeyGate 开发登录</title><h1>ExKeyGate 开发登录</h1><p>这里只验证登录和会话，不授予管理或审批权限。</p><a href="/auth/login">通过 SSO 登录</a><p><a href="/auth/session">查看当前会话</a></p></html>`))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		origin, _ := url.Parse(s.origin)
		if r.TLS == nil || r.Host != origin.Host {
			fail(w, 400)
			return
		}
		id := "req-" + hexToken()
		w.Header().Set("X-Request-ID", id)
		ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), requestIDKey{}, id), 15*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Service) login(w http.ResponseWriter, r *http.Request) { s.startLogin(w, r, nil) }
func (s *Service) startLogin(w http.ResponseWriter, r *http.Request, browserContext *storage.BrowserLoginContext) {
	if r.URL.RawQuery != "" {
		fail(w, 400)
		return
	}
	state, browser, nonce, verifier := random(), random(), random(), random()
	id := requestID(r)
	stateHash := hash(state)
	rawVerifier, _ := parse(verifier)
	envelope, err := s.protector.Seal(r.Context(), binding(s.config.Environment, stateHash), rawVerifier[:], "anonymous", id)
	if err != nil {
		s.rejected(r, "pkce_seal", "root_budget_or_protection_unavailable", hex.EncodeToString(stateHash[:]))
		fail(w, 503)
		return
	}
	encrypted, err := json.Marshal(envelope)
	if err != nil {
		fail(w, 503)
		return
	}
	record := storage.LoginState{BrowserContext: browserContext, StateHash: stateHash, BrowserHash: hash(browser), ProfileHash: s.profile, Nonce: nonce, VerifierCipher: encrypted}
	if err = s.store.CreateLogin(r.Context(), record, audit(id, "anonymous", "login_create", hex.EncodeToString(stateHash[:]), "pending")); err != nil {
		s.rejected(r, "login_create", "transaction_or_audit_unavailable", hex.EncodeToString(stateHash[:]))
		fail(w, 503)
		return
	}
	setCookie(w, loginCookie, browser, 300, http.SameSiteLaxMode)
	// 管理入口要求身份平台重新认证；回调仍核验 auth_time，不能仅信任 prompt 请求已被执行。
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("acr_values", strings.Join(s.config.Identity.AllowedACR, " ")), oauth2.SetAuthURLParam("max_age", strconv.FormatInt(int64(s.config.Identity.MaxAuthAge/time.Second), 10))}
	if browserContext == nil {
		options = append(options, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	target := s.oauth.AuthCodeURL(state, options...)
	http.Redirect(w, r, target, 303)
}
func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > 8192 {
		fail(w, 400)
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(w, 400)
		return
	}
	for key, value := range values {
		if len(value) != 1 || (key != "code" && key != "state" && key != "error" && key != "error_description" && key != "iss") {
			fail(w, 400)
			return
		}
	}
	state := values.Get("state")
	if _, ok := parse(state); !ok {
		fail(w, 400)
		return
	}
	browser, ok := cookie(r, loginCookie)
	if !ok {
		fail(w, 401)
		return
	}
	if values.Get("iss") != "" && values.Get("iss") != s.config.Identity.Issuer {
		fail(w, 400)
		return
	}
	if (values.Get("code") == "" && values.Get("error") == "") || len(values.Get("code")) > 2048 {
		fail(w, 400)
		return
	}
	id := requestID(r)
	stateHash := hash(state)
	record, err := s.store.ConsumeLogin(r.Context(), stateHash, hash(browser), s.profile, audit(id, "anonymous", "login_consume", hex.EncodeToString(stateHash[:]), "consumed"))
	if err != nil {
		s.rejected(r, "login_consume", "transaction_unavailable_or_expired", hex.EncodeToString(stateHash[:]))
		fail(w, 401)
		return
	}
	setCookie(w, loginCookie, "", -1, http.SameSiteLaxMode)
	if values.Get("error") != "" {
		fail(w, 401)
		return
	}
	var envelope keycrypto.Envelope
	if json.Unmarshal(record.VerifierCipher, &envelope) != nil {
		fail(w, 503)
		return
	}
	rawVerifier, err := s.protector.Open(r.Context(), binding(s.config.Environment, stateHash), envelope)
	if err != nil || len(rawVerifier) != 32 {
		s.rejected(r, "pkce_open", "scope_or_ciphertext_invalid", hex.EncodeToString(stateHash[:]))
		fail(w, 503)
		return
	}
	verifier := base64.RawURLEncoding.EncodeToString(rawVerifier)
	clear(rawVerifier)
	tokenContext := context.WithValue(r.Context(), oauth2.HTTPClient, s.client)
	tokens, err := s.oauth.Exchange(tokenContext, values.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		s.rejected(r, "token_exchange", "issuer_exchange_failed", hex.EncodeToString(stateHash[:]))
		fail(w, 401)
		return
	}
	rawIDToken, ok := tokens.Extra("id_token").(string)
	if !ok {
		fail(w, 401)
		return
	}
	principal, err := s.verifier.VerifyLogin(r.Context(), rawIDToken, record.Nonce)
	if err != nil {
		s.rejected(r, "token_verify", "identity_claims_invalid", hex.EncodeToString(stateHash[:]))
		fail(w, 401)
		return
	}
	if record.BrowserContext == nil && (record.StartedAt.IsZero() || principal.AuthenticatedAt.Before(record.StartedAt.Add(-30*time.Second))) {
		s.rejected(r, "token_verify", "fresh_authentication_required", hex.EncodeToString(stateHash[:]))
		fail(w, 401)
		return
	}
	if record.BrowserContext != nil {
		s.completeBrowserLogin(w, r, principal.ID, principal.AuthenticatedAt, *record.BrowserContext)
		return
	}
	sessionToken := random()
	sessionHash := hash(sessionToken)
	session, err := s.store.CreateSession(r.Context(), sessionHash, s.profile, principal.ID, principal.AuthenticatedAt, audit(id, principal.ID, "session_create", hex.EncodeToString(sessionHash[:]), "success"))
	if err != nil {
		s.rejected(r, "session_create", "transaction_or_audit_unavailable", hex.EncodeToString(sessionHash[:]))
		fail(w, 503)
		return
	}
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 1 {
		fail(w, 401)
		return
	}
	setCookie(w, sessionCookie, sessionToken, maxAge, http.SameSiteStrictMode)
	s.completed(r.Context(), id, principal.ID, hex.EncodeToString(sessionHash[:]), "session_create")
	if s.flow != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html lang="zh"><meta charset="utf-8"><p>身份已验证，业务权限按当前授权检查。</p><a href="/manage">进入开发管理</a></html>`))
		return
	}
	// 第一方确认页让后续显式点击成为同站导航，避免跨站 IdP 跳转链影响 Strict Cookie。
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html lang="zh"><meta charset="utf-8"><title>登录完成</title><p>登录成功，身份已验证；尚未授予管理或审批权限。</p><a href="/auth/session">查看当前会话</a></html>`))
}
func (s *Service) session(w http.ResponseWriter, r *http.Request) {
	token, ok := cookie(r, sessionCookie)
	if !ok {
		fail(w, 401)
		return
	}
	session, err := s.store.Session(r.Context(), hash(token), s.profile)
	if err != nil {
		fail(w, 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"principalId": session.PrincipalID, "authenticatedAt": session.AuthenticatedAt, "expiresAt": session.ExpiresAt, "csrfToken": csrf(token), "managementAuthorized": s.managementAuthorized(r, token)})
}
func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.Header.Get("Origin") != s.origin {
		fail(w, 403)
		return
	}
	token, ok := cookie(r, sessionCookie)
	if !ok {
		fail(w, 401)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf(token))) != 1 {
		fail(w, 403)
		return
	}
	sessionHash := hash(token)
	session, err := s.store.Session(r.Context(), sessionHash, s.profile)
	if err != nil {
		fail(w, 401)
		return
	}
	id := requestID(r)
	if err = s.store.RevokeSession(r.Context(), sessionHash, s.profile, audit(id, session.PrincipalID, "session_revoke", hex.EncodeToString(sessionHash[:]), "revoked")); err != nil {
		s.rejected(r, "session_revoke", "transaction_or_audit_unavailable", hex.EncodeToString(sessionHash[:]))
		fail(w, 503)
		return
	}
	setCookie(w, sessionCookie, "", -1, http.SameSiteStrictMode)
	s.completed(r.Context(), id, session.PrincipalID, hex.EncodeToString(sessionHash[:]), "session_revoke")
	w.WriteHeader(204)
}

// managementAuthorized 仅用于界面提示，所有业务读写仍独立查库鉴权。
func (s *Service) managementAuthorized(r *http.Request, token string) bool {
	if s.flow == nil {
		return false
	}
	_, e := s.flow.control.Profiles(r.Context(), token)
	return e == nil
}
