package webauth

import (
	"ex-keygate/internal/passport"
	"ex-keygate/internal/storage"
	"net/http"
)

func (s *Service) ConfigurePassport(p *passport.Client) error {
	if s.handlerStarted.Load() || s.flow == nil {
		return ErrConfig
	}
	return s.flow.control.ConfigurePassport(p)
}
func (s *Service) passportRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /api/requests/{id}/passport-result", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		if s.flow == nil {
			s.businessError(w, r, storage.ErrDenied)
			return
		}
		out, e := s.flow.control.PassportOutcome(r.Context(), token, r.PathValue("id"))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
}
