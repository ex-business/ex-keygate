package webauth

import (
	"context"
	"errors"
	"ex-keygate/internal/storage"
	"net/http"
	"time"
)

func (s *Service) auditRoutes(handle func(string, http.HandlerFunc)) {
	handle("POST /api/audit/query", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var f storage.AuditFilter
		if e := strictJSON(w, r, &f); e != nil {
			s.businessError(w, r, e)
			return
		}
		out, e := s.flow.control.AuditQuery(r.Context(), token, f)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/audit/exports", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var f storage.AuditFilter
		if e := strictJSON(w, r, &f); e != nil {
			s.businessError(w, r, e)
			return
		}
		out, e := s.flow.control.ExportAudit(r.Context(), token, f, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 201, out)
	})
	handle("GET /api/audit/exports", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.AuditExports(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("GET /api/audit/exports/{id}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.DownloadAudit(r.Context(), token, r.PathValue("id"), requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="keygate-audit.jsonl"`)
		w.WriteHeader(200)
		_, _ = w.Write(out)
	})
	handle("GET /api/audit/auth-failures", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.AuthFailures(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
}

// 审计聚合失败不能把认证拒绝改为成功，也不泄露原请求头或客户端自报身份。
func (s *Service) recordAuthFailure(r *http.Request, e error) {
	reason := "denied"
	if !errors.Is(e, storage.ErrDenied) {
		reason = "unavailable"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Second)
	defer cancel()
	if err := s.flow.control.RecordAuthFailure(ctx, reason, requestID(r)); err != nil {
		s.rejected(r, "auth_failure_audit", "aggregation_unavailable", "")
	}
}
