package webauth

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"errors"
	"ex-keygate/internal/identity"
	"ex-keygate/internal/storage"
	"net/http"
	"time"
)

//go:embed login.html
var loginHTML []byte

//go:embed login.css
var loginCSS []byte

//go:embed login.js
var loginJS []byte

const passwordCSRFCookie = "__Host-keygate_password_csrf"

type LocalAccountPlan struct {
	Accounts []LocalAccountEnrollment `json:"accounts"`
}
type LocalAccountEnrollment struct {
	Username     string `json:"username"`
	Subject      string `json:"subject"`
	PasswordHash string `json:"passwordHash"`
}

// ProvisionLocalAccountsOffline 只在监听前把离线核验的账号映射至已有人员；配置中仅接收摘要。
func (s *Service) ProvisionLocalAccountsOffline(ctx context.Context, plan LocalAccountPlan) error {
	if s.handlerStarted.Load() || s.flow == nil || s.localAccounts {
		return ErrConfig
	}
	accounts := make([]storage.LocalAccount, 0, len(plan.Accounts))
	for _, a := range plan.Accounts {
		if a.Subject == "" || len(a.Subject) > 256 {
			return ErrConfig
		}
		accounts = append(accounts, storage.LocalAccount{Username: a.Username, PrincipalID: identity.PrincipalID(s.config.Identity.Issuer, a.Subject), PasswordHash: a.PasswordHash})
	}
	if e := s.flow.control.ProvisionLocalAccountsOffline(ctx, accounts, "local-account-provision-"+hexToken()); e != nil {
		return e
	}
	s.localAccounts = true
	return nil
}
func (s *Service) loginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(loginHTML)
}
func (s *Service) localLoginRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /login.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(loginCSS)
	})
	mux.HandleFunc("GET /login.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(loginJS)
	})
	mux.HandleFunc("GET /auth/options", func(w http.ResponseWriter, r *http.Request) {
		token := random()
		setCookie(w, passwordCSRFCookie, token, 600, http.SameSiteStrictMode)
		businessJSON(w, 200, map[string]any{"password": s.localAccounts, "sso": true, "simulatedSSO": s.config.Identity.DevelopmentMode, "csrfToken": csrf(token)})
	})
	mux.HandleFunc("POST /auth/password", s.passwordLogin)
}
func (s *Service) passwordLogin(w http.ResponseWriter, r *http.Request) {
	// 登录同样校验Origin及浏览器绑定的CSRF，防止攻击者让受害者登录攻击者账号。
	token, ok := cookie(r, passwordCSRFCookie)
	if !ok || r.URL.RawQuery != "" || r.Header.Get("Origin") != s.origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf(token))) != 1 {
		fail(w, 403)
		return
	}
	if !s.localAccounts || s.flow == nil {
		fail(w, 503)
		return
	}
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
	default:
		fail(w, 429)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if e := strictJSON(w, r, &body); e != nil {
		fail(w, 400)
		return
	}
	newToken := random()
	var previous [32]byte
	if old, valid := cookie(r, sessionCookie); valid {
		previous = hash(old)
	}
	session, e := s.flow.control.PasswordSession(r.Context(), body.Username, body.Password, hash(newToken), previous, requestID(r))
	body.Password = ""
	if e != nil {
		if errors.Is(e, storage.ErrCredentials) {
			s.rejected(r, "password_login", "credentials_rejected", "")
			fail(w, 401)
		} else {
			s.rejected(r, "password_login", "security_state_unavailable", "")
			fail(w, 503)
		}
		return
	}
	setCookie(w, sessionCookie, newToken, int(time.Until(session.ExpiresAt).Seconds()), http.SameSiteStrictMode)
	setCookie(w, passwordCSRFCookie, "", -1, http.SameSiteStrictMode)
	s.completed(r.Context(), requestID(r), session.PrincipalID, "local-login", "password_verified")
	businessJSON(w, 200, map[string]string{"next": "mfa"})
}
