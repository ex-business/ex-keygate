package webauth

import (
	"bytes"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"ex-keygate/internal/httpsign"
	"ex-keygate/internal/storage"
	"github.com/jackc/pgx/v5/pgconn"
)

const probeAudience = "keygate-probe"

func businessJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Service) businessError(w http.ResponseWriter, r *http.Request, e error) {
	status := 503
	switch {
	case errors.Is(e, storage.ErrDenied):
		status = 403
	case errors.Is(e, storage.ErrInvalid):
		status = 400
	case errors.Is(e, storage.ErrConflict):
		status = 409
	case errors.Is(e, sql.ErrNoRows):
		status = 404
	default:
		var pg *pgconn.PgError
		if errors.As(e, &pg) && pg.Code == "23505" {
			status = 409
		}
	}
	s.rejected(r, "business_request", "operation_rejected", "")
	businessJSON(w, status, map[string]any{"error": http.StatusText(status), "requestId": requestID(r)})
}

// strictJSON 拒绝重复字段、未知字段、多个 JSON 值和无效 UTF-8；请求不允许隐式改写待批准内容。
func strictJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0 || len(r.Trailer) != 0 {
		return storage.ErrInvalid
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil || !utf8.Valid(raw) || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' || !unicodeEscapes(raw) || !exactFields(raw, target) {
		return storage.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if e = uniqueJSON(d, 0); e != nil {
		return storage.ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return storage.ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(target); e != nil {
		return storage.ErrInvalid
	}
	return nil
}
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return storage.ErrInvalid
	}
	token, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return storage.ErrInvalid
			}
			seen[name] = true
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return storage.ErrInvalid
		}
	case '[':
		for d.More() {
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return storage.ErrInvalid
		}
	default:
		return storage.ErrInvalid
	}
	return nil
}

// businessSession 复用现有 Cookie 表示；写操作必须同时验证固定 Origin 和会话绑定 CSRF。
// 不从 JSON、Bearer、查询参数或请求自报 actor 获取管理身份。
func (s *Service) businessSession(w http.ResponseWriter, r *http.Request, write bool) (string, bool) {
	token, ok := cookie(r, sessionCookie)
	if !ok {
		fail(w, 401)
		return "", false
	}
	if _, e := s.store.Session(r.Context(), hash(token), s.profile); e != nil {
		if !errors.Is(e, storage.ErrSession) {
			s.businessError(w, r, e)
			return "", false
		}
		fail(w, 401)
		return "", false
	}
	if write && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != s.origin || len(r.Header.Values("X-CSRF-Token")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf(token))) != 1) {
		fail(w, 403)
		return "", false
	}
	return token, true
}
func (s *Service) flowRoutes(mux *http.ServeMux) {
	f := s.flow
	f.mu.Lock()
	f.sealed = true
	f.mu.Unlock()
	handle := func(pattern string, next http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "" || r.URL.ForceQuery {
				fail(w, 400)
				return
			}
			if !f.limiter.allow() {
				w.Header().Set("Retry-After", "1")
				fail(w, 429)
				return
			}
			next(w, r)
		})
	}
	s.providerRoutes(handle)
	s.lifecycleRoutes(handle)
	s.auditRoutes(handle)
	handle("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		profiles, e := f.control.Profiles(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, map[string]any{"developmentOnly": true, "simulatedApprovals": true, "environment": f.environment, "rootId": func() string { _, root := f.keySnapshot(); return root }(), "audience": probeAudience, "profiles": profiles})
	})
	handle("GET /api/clients", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := f.control.Clients(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("GET /api/clients/{client}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := f.control.Client(r.Context(), token, r.PathValue("client"))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("GET /api/clients/{client}/keys/{version}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		version, e := strconv.ParseUint(r.PathValue("version"), 10, 64)
		if e != nil {
			fail(w, 400)
			return
		}
		out, e := f.control.Key(r.Context(), token, r.PathValue("client"), version)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("GET /api/requests", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := f.control.Requests(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("GET /api/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := f.control.Request(r.Context(), token, r.PathValue("id"))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/requests", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var op storage.ControlOperation
		if e := strictJSON(w, r, &op); e != nil {
			s.businessError(w, r, e)
			return
		}
		if len(r.Header.Values("X-Idempotency-Key")) != 1 {
			fail(w, 400)
			return
		}
		out, e := f.control.Submit(r.Context(), token, op, r.Header.Get("X-Idempotency-Key"), requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 201, out)
	})
	handle("POST /api/requests/{id}/votes", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var input struct {
			Digest string `json:"digest"`
			Accept *bool  `json:"accept"`
		}
		if e := strictJSON(w, r, &input); e != nil || input.Accept == nil {
			s.businessError(w, r, storage.ErrInvalid)
			return
		}
		out, e := f.control.Vote(r.Context(), token, r.PathValue("id"), input.Digest, *input.Accept, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/requests/{id}/execute", s.executeBusiness)
	handle("POST /api/clients/{client}/emergency-disable", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var input struct{}
		if e := strictJSON(w, r, &input); e != nil {
			s.businessError(w, r, e)
			return
		}
		if e := f.control.EmergencyDisableClient(r.Context(), token, r.PathValue("client"), requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
	})
	handle("GET /api/deliveries/{id}/challenge", func(w http.ResponseWriter, r *http.Request) {
		out, e := f.control.DeliveryChallenge(r.Context(), r.PathValue("id"))
		if e != nil {
			s.businessError(w, r, storage.ErrDenied)
			return
		}
		businessJSON(w, 200, map[string]any{"input": out})
	})
	handle("POST /api/deliveries/{id}/claim", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Signature []byte `json:"signature"`
		}
		if e := strictJSON(w, r, &input); e != nil {
			s.businessError(w, r, e)
			return
		}
		out, e := f.control.ClaimDelivery(r.Context(), r.PathValue("id"), input.Signature, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/deliveries/{id}/confirm", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			MAC []byte `json:"mac"`
		}
		if e := strictJSON(w, r, &input); e != nil {
			s.businessError(w, r, e)
			return
		}
		keys, _ := f.keySnapshot()
		e := storage.ErrDenied
		for _, k := range keys {
			e = k.ConfirmPossession(r.Context(), r.PathValue("id"), input.MAC, requestID(r))
			if e == nil || !errors.Is(e, storage.ErrDenied) {
				break
			}
		}
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
	})
	handle("POST /api/auth/probe", func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, httpsign.MaxBody))
		if e != nil {
			fail(w, 413)
			return
		}
		keys, _ := f.keySnapshot()
		e = storage.ErrDenied
		for _, k := range keys {
			e = k.AuthenticateProbeTraced(r.Context(), r, body, probeAudience, requestID(r))
			if e == nil || !errors.Is(e, storage.ErrDenied) {
				break
			}
		}
		if e != nil {
			s.recordAuthFailure(r, e)
			if errors.Is(e, storage.ErrDenied) {
				fail(w, 401)
			} else {
				s.businessError(w, r, e)
			}
			return
		}
		businessJSON(w, 200, map[string]any{"authenticated": true, "requestId": requestID(r)})
	})
	mux.HandleFunc("GET /manage", s.managePage)
	mux.HandleFunc("GET /manage.js", s.manageScript)
}
func (s *Service) executeBusiness(w http.ResponseWriter, r *http.Request) {
	token, ok := s.businessSession(w, r, true)
	if !ok {
		return
	}
	var input struct {
		Digest string `json:"digest"`
	}
	if e := strictJSON(w, r, &input); e != nil {
		s.businessError(w, r, e)
		return
	}
	id := r.PathValue("id")
	record, e := s.flow.control.Request(r.Context(), token, id)
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	var data struct {
		Operation storage.ControlOperation `json:"operation"`
	}
	if e = json.Unmarshal(record.Manifest, &data); e != nil {
		s.businessError(w, r, storage.ErrInvalid)
		return
	}
	if data.Operation.Kind == storage.IssueKey || data.Operation.Kind == storage.RecoverIssue {
		k := s.flow.keyFor(data.Operation.RootID)
		if k == nil {
			e = storage.ErrDenied
		} else {
			e = k.ExecuteIssueRequested(r.Context(), token, id, input.Digest, requestID(r))
		}
	} else if data.Operation.Kind == storage.ProvisionRoot {
		// 同进程重试复用已注册材料；跨进程不能猜测或重新生成同名根。
		s.flow.mu.Lock()
		if record.Executed && s.flow.roots[data.Operation.RootID] != nil {
			e = s.flow.control.ExecuteRequested(r.Context(), token, id, input.Digest, requestID(r))
		} else {
			var k *storage.DevelopmentKeys
			k, e = s.flow.control.ProvisionSoftwareRootRequested(r.Context(), token, id, input.Digest, requestID(r), s.protector.RootID())
			if e == nil {
				s.flow.roots[data.Operation.RootID] = k
				s.flow.rootID = data.Operation.RootID
			}
		}
		s.flow.mu.Unlock()
	} else {
		e = s.flow.control.ExecuteRequested(r.Context(), token, id, input.Digest, requestID(r))
	}
	if e != nil {
		s.businessError(w, r, e)
		return
	}
	businessJSON(w, 200, map[string]any{"executed": true, "requestId": id})
}

// JSON 的孤立代理项会被标准解码器替换；先拒绝，避免申请内容在入库前被静默改写。
func unicodeEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
	}
	return true
}

// Go 结构体解码默认忽略字段名大小写；接口只接受精确 JSON schema，避免 Kind/Accept 别名覆盖。
func exactFields(raw []byte, target any) bool {
	typ := reflect.TypeOf(target)
	if typ == nil || typ.Kind() != reflect.Pointer || typ.Elem().Kind() != reflect.Struct {
		return false
	}
	typ = typ.Elem()
	allowed := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if tag == "" {
			tag = field.Name
		}
		allowed[tag] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, e := d.Token(); e != nil || token != json.Delim('{') {
		return false
	}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return false
		}
		name, ok := key.(string)
		if !ok || !allowed[name] {
			return false
		}
		if e = uniqueJSON(d, 1); e != nil {
			return false
		}
	}
	_, e := d.Token()
	return e == nil
}
