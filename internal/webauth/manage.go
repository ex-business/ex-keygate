package webauth

import (
	_ "embed"
	"net/http"
)

//go:embed manage.html
var managementHTML []byte

//go:embed manage.js
var managementJS []byte

func (s *Service) managePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(managementHTML)
}
func (s *Service) manageScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(managementJS)
}
