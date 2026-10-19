package webauth

import (
	"ex-keygate/internal/mfa"
	"net/http"
)

func (s *Service) consoleRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /api/console/identity", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		identity, e := s.flow.control.ConsoleIdentity(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		available := map[string]bool{}
		for _, method := range []mfa.Method{mfa.Email, mfa.SMS, mfa.TOTP, mfa.Hardware} {
			available[string(method)] = s.config.MFAPlugins.Available(method)
		}
		businessJSON(w, 200, map[string]any{"identity": identity, "environment": s.flow.environment, "developmentOnly": true, "simulatedIdentity": s.config.Identity.DevelopmentMode, "available": available})
	})
	handle("GET /api/console/settings", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.ConsoleSettings(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
}
