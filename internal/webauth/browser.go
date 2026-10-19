package webauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"ex-keygate/internal/storage"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// H5 Cookie 名同时绑定安全域与客户端，多个应用共存时不会互相覆盖；不对脚本暴露会话秘密。
func (s *Service) browserCookie(client string) string {
	h := sha256.Sum256([]byte(s.flow.environment + "\x00" + client))
	return "__Host-keygate_h5_" + hex.EncodeToString(h[:16])
}
func (s *Service) browserCSRF(client, token string) string {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte("keygate-h5-csrf-v1\x00" + s.flow.environment + "\x00" + client + "\x00" + s.profile))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

var browserClientID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var browserReturnPath = regexp.MustCompile(`^/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]*$`)

func (s *Service) browserLanding(client string) string {
	if path := s.config.BrowserReturnPaths[client]; path != "" {
		return path
	}
	return "/h5?" + url.Values{"client": []string{client}}.Encode()
}
func (s *Service) browserError(w http.ResponseWriter, r *http.Request, e error) {
	if errors.Is(e, storage.ErrDenied) {
		s.rejected(r, "browser_session", "session_unavailable", "")
		fail(w, 401)
		return
	}
	s.businessError(w, r, e)
}

// browserOrigin 不启用跨域凭据，也不因 SameSite 相同而放宽端口和子域；写操作还必须核验用途绑定 CSRF。
func (s *Service) browserOrigin(w http.ResponseWriter, r *http.Request, write bool) bool {
	if values := r.Header.Values("Origin"); len(values) > 1 || len(values) == 1 && values[0] != s.origin {
		fail(w, 403)
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		fail(w, 403)
		return false
	}
	if write && len(r.Header.Values("Origin")) != 1 {
		fail(w, 403)
		return false
	}
	return true
}
func (s *Service) browserCredential(w http.ResponseWriter, r *http.Request, client string, write bool) (string, bool) {
	if !s.browserOrigin(w, r, write) {
		return "", false
	}
	token, ok := cookie(r, s.browserCookie(client))
	if !ok {
		fail(w, 401)
		return "", false
	}
	if write && (len(r.Header.Values("X-CSRF-Token")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.browserCSRF(client, token))) != 1) {
		fail(w, 403)
		return "", false
	}
	return token, true
}
func (s *Service) browserResponse(w http.ResponseWriter, code int, client, token string, session storage.BrowserSession) {
	businessJSON(w, code, map[string]any{"clientId": session.ClientID, "principalId": session.PrincipalID, "authenticatedAt": session.AuthenticatedAt, "expiresAt": session.ExpiresAt, "csrfToken": s.browserCSRF(client, token)})
}
func (s *Service) setBrowserCookie(w http.ResponseWriter, client, token string, session storage.BrowserSession) bool {
	age := int(time.Until(session.ExpiresAt).Seconds())
	if age < 1 {
		return false
	}
	setCookie(w, s.browserCookie(client), token, age, http.SameSiteStrictMode)
	return true
}
func (s *Service) browserLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400)
		return
	}
	if !s.browserOrigin(w, r, false) {
		return
	}
	snapshot, e := s.flow.control.BrowserLoginSnapshot(r.Context(), r.PathValue("client"))
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	s.startLogin(w, r, &snapshot)
}
func (s *Service) browserRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /h5/login/{client}", s.browserLogin)
	handle("POST /api/browser/{client}/session", func(w http.ResponseWriter, r *http.Request) {
		if !s.browserOrigin(w, r, true) {
			return
		}
		identity, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var body struct{}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		client := r.PathValue("client")
		token := random()
		old := ""
		if value, ok := cookie(r, s.browserCookie(client)); ok {
			old = value
		}
		session, e := s.flow.control.CreateBrowserSession(r.Context(), identity, client, token, old, 0, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		if !s.setBrowserCookie(w, client, token, session) {
			fail(w, 401)
			return
		}
		s.browserResponse(w, 201, client, token, session)
	})
	handle("GET /api/browser/{client}/session", func(w http.ResponseWriter, r *http.Request) {
		client := r.PathValue("client")
		token, ok := s.browserCredential(w, r, client, false)
		if !ok {
			return
		}
		session, e := s.flow.control.BrowserSession(r.Context(), client, token)
		if e != nil {
			s.browserError(w, r, e)
			return
		}
		s.browserResponse(w, 200, client, token, session)
	})
	handle("POST /api/browser/{client}/authenticate", func(w http.ResponseWriter, r *http.Request) {
		client := r.PathValue("client")
		token, ok := s.browserCredential(w, r, client, true)
		if !ok {
			return
		}
		var body struct{}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		session, e := s.flow.control.AuthenticateBrowser(r.Context(), client, token, requestID(r))
		if e != nil {
			s.browserError(w, r, e)
			return
		}
		businessJSON(w, 200, map[string]any{"authenticated": true, "clientId": session.ClientID, "principalId": session.PrincipalID, "expiresAt": session.ExpiresAt})
	})
	handle("POST /api/browser/{client}/logout", func(w http.ResponseWriter, r *http.Request) {
		client := r.PathValue("client")
		token, ok := s.browserCredential(w, r, client, true)
		if !ok {
			return
		}
		var body struct{}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		if e := s.flow.control.RevokeBrowserSession(r.Context(), client, token, requestID(r)); e != nil {
			s.browserError(w, r, e)
			return
		}
		setCookie(w, s.browserCookie(client), "", -1, http.SameSiteStrictMode)
		w.WriteHeader(204)
	})
}

// completeBrowserLogin 在 PKCE/nonce/ID Token 验证后调用，回调只使用服务端冻结的客户端上下文。
func (s *Service) completeBrowserLogin(w http.ResponseWriter, r *http.Request, principal string, authenticatedAt time.Time, context storage.BrowserLoginContext) bool {
	if s.flow == nil || context.Environment != s.flow.environment {
		fail(w, 401)
		return false
	}
	client := context.ClientID
	identity := random()
	token := random()
	old := ""
	if value, ok := cookie(r, s.browserCookie(client)); ok {
		old = value
	}
	session, e := s.flow.control.CompleteBrowserLogin(r.Context(), context, principal, authenticatedAt, identity, token, old, requestID(r))
	if e != nil {
		s.browserError(w, r, e)
		return false
	}
	if !s.setBrowserCookie(w, client, token, session) {
		fail(w, 401)
		return false
	}
	setCookie(w, sessionCookie, identity, int(time.Until(session.ExpiresAt).Seconds()), http.SameSiteStrictMode)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html lang="zh"><meta charset="utf-8"><title>H5登录完成</title><p>H5身份已验证。点击继续进入应用。</p><a href="` + html.EscapeString(s.browserLanding(client)) + `">继续进入H5应用</a></html>`))
	return true
}
