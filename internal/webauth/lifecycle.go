package webauth

import "net/http"

func (s *Service) lifecycleRoutes(handle func(string, http.HandlerFunc)) {
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
