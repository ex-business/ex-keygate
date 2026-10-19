package webauth

import (
	"ex-keygate/internal/storage"
	"net/http"
)

func (s *Service) lifecycleRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /api/clients/{client}/recoveries", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.Recoveries(r.Context(), token, r.PathValue("client"))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/recoveries/{id}/abort", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var in struct{}
		if e := strictJSON(w, r, &in); e != nil {
			s.businessError(w, r, e)
			return
		}
		if e := s.flow.control.AbortRecovery(r.Context(), token, r.PathValue("id"), requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
	})

	handle("POST /api/revocations", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var in storage.RevocationInput
		if e := strictJSON(w, r, &in); e != nil {
			s.businessError(w, r, e)
			return
		}
		if e := s.flow.control.Revoke(r.Context(), token, in, requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
	})
	handle("GET /api/clients/{client}/lifecycle", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.Lifecycle(r.Context(), token, r.PathValue("client"))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/lifecycle/maintain", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var in struct{}
		if e := strictJSON(w, r, &in); e != nil {
			s.businessError(w, r, e)
			return
		}
		if e := s.flow.control.MaintainLifecycle(r.Context(), token, requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
	})
}
