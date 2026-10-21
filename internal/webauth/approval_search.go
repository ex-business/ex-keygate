package webauth

import (
	"ex-keygate/internal/storage"
	"net/http"
	"net/url"
	"strconv"
)

// 分页查询单独注册白名单只读路由，不放宽既有业务wrapper；继续使用统一限流及本人验证。
func (s *Service) approvalSearchRoutes(mux *http.ServeMux) {
	for _, kind := range []string{"requests", "notifications"} {
		mux.HandleFunc("GET /api/"+kind+"/search", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.ForceQuery || len(r.URL.RawQuery) > 2048 {
				fail(w, 400)
				return
			}
			values, e := url.ParseQuery(r.URL.RawQuery)
			if e != nil {
				fail(w, 400)
				return
			}
			for k, v := range values {
				switch k {
				case "q", "from", "until", "state", "view", "unread", "limit", "cursor":
				default:
					fail(w, 400)
					return
				}
				if len(v) != 1 {
					fail(w, 400)
					return
				}
			}
			if !s.flow.limiter.allow() {
				w.Header().Set("Retry-After", "1")
				fail(w, 429)
				return
			}
			token, ok := s.businessSession(w, r, false)
			if !ok {
				return
			}
			f := storage.SearchFilter{Query: values.Get("q"), From: values.Get("from"), Until: values.Get("until"), State: values.Get("state"), View: values.Get("view"), Cursor: values.Get("cursor")}
			if raw := values.Get("limit"); raw != "" {
				f.Limit, e = strconv.Atoi(raw)
				if e != nil || f.Limit == 0 {
					fail(w, 400)
					return
				}
			}
			if raw := values.Get("unread"); raw != "" {
				if raw != "true" && raw != "false" {
					fail(w, 400)
					return
				}
				f.Unread = raw == "true"
			}
			if kind == "requests" {
				out, e := s.flow.control.SearchRequests(r.Context(), token, f)
				if e != nil {
					s.businessError(w, r, e)
					return
				}
				businessJSON(w, 200, out)
			} else {
				out, e := s.flow.control.SearchNotifications(r.Context(), token, f)
				if e != nil {
					s.businessError(w, r, e)
					return
				}
				businessJSON(w, 200, out)
			}
		})
	}
}
