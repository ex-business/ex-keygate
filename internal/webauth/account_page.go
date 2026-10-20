package webauth

import (
	_ "embed"
	"net/http"
)

//go:embed account.html
var accountHTML []byte

//go:embed account.css
var accountCSS []byte

//go:embed account.js
var accountJS []byte

func (s *Service) accountPages(handle func(string, http.HandlerFunc)) {
	handle("GET /account-setup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(accountHTML)
	})
	handle("GET /account.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(accountCSS)
	})
	handle("GET /account.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(accountJS)
	})
}
