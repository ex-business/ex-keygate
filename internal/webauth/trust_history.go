package webauth

import (
	"encoding/pem"
	"ex-keygate/internal/storage"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

func trustVersion(raw string) (uint64, error) {
	n, e := strconv.ParseUint(raw, 10, 64)
	if e != nil || n == 0 || n > 9007199254740991 || strconv.FormatUint(n, 10) != raw {
		return 0, storage.ErrInvalid
	}
	return n, nil
}
func trustQuery(r *http.Request, allowed ...string) bool {
	if r.URL.ForceQuery || len(r.URL.RawQuery) > 256 {
		return false
	}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return false
	}
	for key, values := range query {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
			}
		}
		if !found || len(values) != 1 {
			return false
		}
	}
	return true
}
func (s *Service) trustHistoryRoutes(mux *http.ServeMux) {
	// 仅新增只读证书路由允许白名单查询；既有业务wrapper继续拒绝所有查询参数。
	handle := func(pattern string, next http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.ForceQuery || len(r.URL.RawQuery) > 256 {
				fail(w, 400)
				return
			}
			if !s.flow.limiter.allow() {
				w.Header().Set("Retry-After", "1")
				fail(w, 429)
				return
			}
			next(w, r)
		})
	}
	handle("GET /api/trust/services/{service}/certificates", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		if s.applicationTrust == nil {
			fail(w, 404)
			return
		}
		if !trustQuery(r, "before", "limit") {
			fail(w, 400)
			return
		}
		var before uint64
		limit := 20
		var e error
		if raw := r.URL.Query().Get("before"); raw != "" {
			before, e = trustVersion(raw)
			if e != nil {
				fail(w, 400)
				return
			}
		}
		if raw := r.URL.Query().Get("limit"); raw != "" {
			limit, e = strconv.Atoi(raw)
			if e != nil || strconv.Itoa(limit) != raw {
				fail(w, 400)
				return
			}
		}
		out, e := s.flow.control.TrustCertificateHistory(r.Context(), token, r.PathValue("service"), before, limit)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("GET /api/trust/services/{service}/certificates/{version}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		if s.applicationTrust == nil {
			fail(w, 404)
			return
		}
		version, e := trustVersion(r.PathValue("version"))
		if e != nil || !trustQuery(r) {
			fail(w, 400)
			return
		}
		out, _, e := s.flow.control.TrustCertificateDetail(r.Context(), token, r.PathValue("service"), version, false, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("GET /api/trust/services/{service}/certificates/{version}/download", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		if s.applicationTrust == nil {
			fail(w, 404)
			return
		}
		version, e := trustVersion(r.PathValue("version"))
		format, valid := trustDownloadFormat(r)
		if e != nil || !valid {
			fail(w, 400)
			return
		}
		_, der, e := s.flow.control.TrustCertificateDetail(r.Context(), token, r.PathValue("service"), version, true, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		writeCertificate(w, der, fmt.Sprintf("%s-v%d", r.PathValue("service"), version), format)
		s.logger.InfoContext(r.Context(), "公开业务证书下载完成", "request_id", requestID(r), "service_id", r.PathValue("service"), "version", version, "format", format, "result", "success")
	})
	handle("GET /api/trust/roots/{fingerprint}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		if s.applicationTrust == nil {
			fail(w, 404)
			return
		}
		if !trustQuery(r) {
			fail(w, 400)
			return
		}
		root, info, e := s.flow.control.TrustRootDetail(r.Context(), token, r.PathValue("fingerprint"), false, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, map[string]any{"root": root, "info": info})
	})
	handle("GET /api/trust/roots/{fingerprint}/download", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		if s.applicationTrust == nil {
			fail(w, 404)
			return
		}
		format, valid := trustDownloadFormat(r)
		if !valid {
			fail(w, 400)
			return
		}
		root, _, e := s.flow.control.TrustRootDetail(r.Context(), token, r.PathValue("fingerprint"), true, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		writeCertificate(w, root.Certificate, "root-"+root.Fingerprint, format)
		s.logger.InfoContext(r.Context(), "公开根证书下载完成", "request_id", requestID(r), "root_fingerprint", root.Fingerprint, "format", format, "result", "success")
	})
}
func trustDownloadFormat(r *http.Request) (string, bool) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "pem"
	}
	return format, trustQuery(r, "format") && (format == "pem" || format == "der")
}

// 下载仅编码已授权查询到的公开DER，不读取运行目录或任何私钥文件。
func writeCertificate(w http.ResponseWriter, der []byte, name, format string) {
	content := der
	w.Header().Set("Content-Type", "application/pkix-cert")
	if format == "pem" {
		content = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		w.Header().Set("Content-Type", "application/x-pem-file")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, name, format))
	w.WriteHeader(200)
	_, _ = w.Write(content)
}
