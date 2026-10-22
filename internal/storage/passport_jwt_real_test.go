package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ex-keygate/internal/passport"
)

func TestPassportJWTRealManagement(t *testing.T) {
	base := os.Getenv("KEYGATE_TEST_PASSPORT_JWT_URL")
	secretFile := os.Getenv("KEYGATE_TEST_PASSPORT_JWT_SECRET_FILE")
	dsn := os.Getenv("KEYGATE_TEST_PASSPORT_JWT_DATABASE_URL")
	if base == "" || secretFile == "" || os.Getenv("KEYGATE_TEST_PASSPORT_OWNED_FIXTURE") != "1" {
		t.Skip("run scripts/test-passport-adapter.py --jwt")
	}
	if !strings.Contains(dsn, "/passport_test?") || !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatal("real JWT test requires explicitly owned loopback fixture")
	}
	raw, e := os.ReadFile(secretFile)
	if e != nil {
		t.Fatal("test credential unavailable")
	}
	secret := strings.TrimSpace(string(raw))
	clear(raw)
	remoteDB, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal("test database unavailable")
	}
	defer remoteDB.Close()
	var public map[string]string
	raw, e = os.ReadFile(os.Getenv("KEYGATE_TEST_PASSPORT_JWT_PUBLIC_FILE"))
	if e != nil || json.Unmarshal(raw, &public) != nil {
		t.Fatal("test public keys unavailable")
	}
	f := newControlFixture(t)
	grantJWTPolicyAdmin(t, f)
	ctx := context.Background()
	transport := &http.Client{Timeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	var posts atomic.Int64
	var cut atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstream, err := http.NewRequestWithContext(r.Context(), r.Method, base+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			w.WriteHeader(503)
			return
		}
		upstream.Header = r.Header.Clone()
		response, err := transport.Do(upstream)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		defer response.Body.Close()
		payload, _ := io.ReadAll(response.Body)
		if r.Method == "POST" {
			posts.Add(1)
			if cut.Swap(false) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		w.Write(payload)
	}))
	defer proxy.Close()
	adapter, e := passport.New(passport.Config{URL: proxy.URL, ClientID: "keygate-jwt-test", Secret: secret, AllowLoopbackHTTP: true})
	if e != nil {
		t.Fatal(e)
	}
	defer adapter.Close()
	if e = f.c.ConfigurePassportJWT(adapter); e != nil {
		t.Fatal(e)
	}
	submit := func(action, kid string, revision uint64) ControlRequest {
		t.Helper()
		op := jwtOperation(action, revision)
		op.JWT.Kid = kid
		if action == "publish" {
			op.JWT.PublicKey = public[kid]
		}
		r, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
		if e != nil {
			t.Fatal(e)
		}
		approveControl(t, f, r)
		return r
	}
	execute := func(r ControlRequest, drop bool) {
		t.Helper()
		if drop {
			cut.Store(true)
			if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e == nil {
				t.Fatal("response loss not observed")
			}
		}
		before := posts.Load()
		if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
			t.Fatal("real JWT execution", e)
		}
		if drop && posts.Load() != before {
			t.Fatal("JWT mutation repeated after confirmed remote commit")
		}
		out, e := f.c.PassportOutcome(ctx, f.tokens[0], r.ID)
		if e != nil || out.State != "succeeded" || out.DeliveryState != "not_required" {
			t.Fatal("missing JWT confirmation", e)
		}
	}
	state, e := f.c.PassportJWTState(ctx, f.tokens[0])
	if e != nil || state.Revision != 2 || state.CurrentKid == nil || *state.CurrentKid != "old" {
		t.Fatal("unexpected fixture ring", e)
	}
	publish := submit("publish", "next", 2)
	execute(publish, true)
	premature := submit("activate", "next", 3)
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], premature.ID, premature.Digest, unique(t)); e == nil {
		t.Fatal("real prepublish lead ignored")
	}
	remoteDB.Exec(`UPDATE passport_jwt_key SET published_at=clock_timestamp()-interval '301 seconds' WHERE kid='next'`)
	activate := submit("activate", "next", 3)
	execute(activate, false)
	prematureRetire := submit("retire", "old", 4)
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], prematureRetire.ID, prematureRetire.Digest, unique(t)); e == nil {
		t.Fatal("real drain deadline ignored")
	}
	// No old-key token is issued in this fixture. Only its conservative deadline
	// is aged; normal expiration/signing proofs live in Passport's keyring suite.
	remoteDB.Exec(`UPDATE passport_jwt_key SET retire_after=clock_timestamp()-interval '1 second',max_token_expiry=clock_timestamp()-interval '31 seconds' WHERE kid='old'`)
	retire := submit("retire", "old", 4)
	execute(retire, false)
	reserve := submit("publish", "reserve", 5)
	execute(reserve, false)
	remoteDB.Exec(`UPDATE passport_jwt_key SET published_at=clock_timestamp()-interval '301 seconds' WHERE kid='reserve'`)
	businessBase := os.Getenv("KEYGATE_TEST_PASSPORT_BUSINESS_URL")
	api := func(method, path string, data any, token string, want int) map[string]any {
		t.Helper()
		var input io.Reader
		if data != nil {
			body, _ := json.Marshal(data)
			input = bytes.NewReader(body)
		}
		r, _ := http.NewRequest(method, businessBase+path, input)
		if data != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, e := transport.Do(r)
		if e != nil {
			t.Fatal("real business request transport")
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("business path %s got %d want %d", path, response.StatusCode, want)
		}
		var out map[string]any
		json.NewDecoder(response.Body).Decode(&out)
		return out
	}
	account := api("POST", "/iam/v1/users", map[string]string{"email": "approved-jwt@example.test", "password": "Synthetic-Approved-JWT-Only-123"}, "", 200)
	tokens := account["data"].(map[string]any)["tokens"].(map[string]any)
	oldToken := tokens["accessToken"].(string)
	api("GET", "/iam/v1/users/self", nil, oldToken, 200)
	revoke := submit("revoke", "next", 6)
	execute(revoke, true)
	api("GET", "/iam/v1/users/self", nil, oldToken, 401)
	api("GET", "/health/ready", nil, "", 503)
	probe, e := transport.Get(base + "/health/executor-ready")
	if e != nil {
		t.Fatal("executor recovery health unavailable")
	}
	io.Copy(io.Discard, probe.Body)
	probe.Body.Close()
	if probe.StatusCode != 200 {
		t.Fatal("signing revoke removed recovery control plane")
	}
	state, e = f.c.PassportJWTState(ctx, f.tokens[0])
	if e != nil || state.CurrentKid != nil || state.Revision != 7 {
		t.Fatal("confirmed emergency state missing", e)
	}
	recover := submit("activate", "reserve", 7)
	execute(recover, false)
	refreshed := api("POST", "/iam/v1/auth/refresh", map[string]any{"refreshToken": tokens["refreshToken"]}, "", 200)
	api("GET", "/iam/v1/users/self", nil, refreshed["data"].(map[string]any)["accessToken"].(string), 200)
	state, e = f.c.PassportJWTState(ctx, f.tokens[0])
	if e != nil || state.CurrentKid == nil || *state.CurrentKid != "reserve" || state.Revision != 8 {
		t.Fatal("approved recovery failed", e)
	}
	var remoteReceipts, localSuccesses int
	remoteDB.QueryRow(`SELECT count(*) FROM passport_jwt_executor_operation WHERE executor_id='keygate-jwt-test'`).Scan(&remoteReceipts)
	f.db.QueryRow(`SELECT count(*) FROM keygate.passport_executions WHERE environment=$1 AND state='succeeded'`, f.c.environment).Scan(&localSuccesses)
	if remoteReceipts != 6 || localSuccesses != 6 {
		t.Fatal("receipt count mismatch", remoteReceipts, localSuccesses)
	}
	var auditBindings int
	remoteDB.QueryRow(`SELECT count(*) FROM passport_audit_outbox WHERE subject_id='executor:keygate-jwt-test' AND length(metadata->>'approvalDigest')=64 AND metadata->>'operationId'<>''`).Scan(&auditBindings)
	if auditBindings != 6 {
		t.Fatal("remote audit lacks approval binding")
	}
}
