package webauth

import (
	_ "embed"
	browserSDK "ex-keygate/sdk/browser"
	"net/http"
)

//go:embed h5.html
var h5HTML []byte

//go:embed h5.js
var h5JavaScript []byte

func (s *Service) h5Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /h5", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.ForceQuery || len(r.URL.RawQuery) > 256 {
			fail(w, 400)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(h5HTML)
	})
	mux.HandleFunc("GET /h5.js", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400)
			return
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(h5JavaScript)
	})
	mux.HandleFunc("GET /sdk/browser.js", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400)
			return
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(browserSDK.JavaScript)
	})
}
