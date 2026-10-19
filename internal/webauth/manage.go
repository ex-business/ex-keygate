package webauth

import (
	_ "embed"
	"net/http"
)

//go:embed manage.html
var managementHTML []byte

//go:embed manage.css
var managementCSS []byte

//go:embed manage.js
var managementJS []byte

func (s *Service) managePage(w http.ResponseWriter, r *http.Request) {
	// 未认证和待MFA身份统一进入登录页；业务API仍独立鉴权，不能靠页面跳转放行。
	token, ok := cookie(r, sessionCookie)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.flow != nil {
		own, e := s.flow.control.ConsoleIdentity(r.Context(), token)
		if e != nil || !own.MFAVerified {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}

	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(managementHTML)
}
func (s *Service) manageScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(managementJS)
}

func (s *Service) manageStyles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(managementCSS)
}
