package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"ex-keygate/internal/passport"
)

// The opt-in runner starts the actual sibling Passport binary, migration CLI,
// executor CLI, PostgreSQL and Redis, never a shared or deployed environment.
func TestPassportRealManagement(t *testing.T) {
	base := os.Getenv("KEYGATE_TEST_PASSPORT_URL")
	secretFile := os.Getenv("KEYGATE_TEST_PASSPORT_EXECUTOR_SECRET_FILE")
	if base == "" || secretFile == "" {
		t.Skip("run scripts/test-passport-adapter.py for real Passport chain")
	}
	raw, e := os.ReadFile(secretFile)
	if e != nil {
		t.Fatal("test secret unavailable")
	}
	key := strings.TrimSpace(string(raw))
	clear(raw)
	f := newControlFixture(t)
	ctx := context.Background()
	recipient, encoded, fp := passportRecipient(t)
	var posts atomic.Int64
	var cut atomic.Bool
	transport := &http.Client{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A response-loss proxy forwards the original POST to the real Passport and
		// consumes its result before dropping the downstream connection.
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
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
	defer transport.CloseIdleConnections()
	adapter, e := passport.New(passport.Config{URL: proxy.URL, ClientID: "keygate-test", Secret: key, AllowLoopbackHTTP: true})
	if e != nil {
		t.Fatal(e)
	}
	defer adapter.Close()
	if e = f.c.ConfigurePassport(adapter); e != nil {
		t.Fatal(e)
	}
	submit := func(operation string, version uint64, target string) ControlRequest {
		t.Helper()
		p := &PassportOperation{Operation: operation}
		if operation == "create" {
			p.Audiences = []string{"trade"}
		}
		if operation != "disable" {
			p.RecipientPublicKey = encoded
			p.RecipientFingerprint = fp
		}
		r, e := f.c.Submit(ctx, f.tokens[0], ControlOperation{Kind: PassportIntrospection, ClientID: target, ExpectedRevision: version, Passport: p}, unique(t), unique(t))
		if e != nil {
			t.Fatal(e)
		}
		approveControl(t, f, r)
		return r
	}
	queryCredential := func(secret string, want int) {
		t.Helper()
		request, _ := http.NewRequest("POST", os.Getenv("KEYGATE_TEST_PASSPORT_BUSINESS_URL")+"/iam/v1/oauth2/introspect", strings.NewReader(`{"token":"invalid"}`))
		request.SetBasicAuth("trade-api", secret)
		request.Header.Set("Content-Type", "application/json")
		response, e := transport.Do(request)
		if e != nil {
			t.Fatal("introspection transport")
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("introspection status=%d want=%d", response.StatusCode, want)
		}
	}
	create := submit("create", 0, "trade-api")
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], create.ID, create.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	out, e := f.c.PassportOutcome(ctx, f.tokens[0], create.ID)
	if e != nil || out.DeliveryState != "encrypted" {
		t.Fatal("real creation delivery", e)
	}
	plain, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, recipient, out.Ciphertext, out.OAEPLabel)
	if e != nil {
		t.Fatal(e)
	}
	old := string(plain)
	clear(plain)
	queryCredential(old, 200)
	rotate := submit("rotate", 1, "trade-api")
	cut.Store(true)
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], rotate.ID, rotate.Digest, unique(t)); e == nil {
		t.Fatal("lost response unexpectedly succeeded")
	}
	before := posts.Load()
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], rotate.ID, rotate.Digest, unique(t)); e != nil {
		t.Fatal("real query recovery", e)
	}
	if posts.Load() != before {
		t.Fatal("POST repeated after remote commit")
	}
	out, e = f.c.PassportOutcome(ctx, f.tokens[0], rotate.ID)
	if e != nil || out.State != "succeeded" || out.DeliveryState != "unavailable" || *out.CommittedRevision != 2 {
		t.Fatal("real recovery mismatch", e)
	}
	queryCredential(old, 401)
	// A replacement rotation is a separately approved action, never an automatic retry.
	replacement := submit("rotate", 2, "trade-api")
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], replacement.ID, replacement.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	out, e = f.c.PassportOutcome(ctx, f.tokens[0], replacement.ID)
	if e != nil {
		t.Fatal(e)
	}
	plain, e = rsa.DecryptOAEP(sha256.New(), rand.Reader, recipient, out.Ciphertext, out.OAEPLabel)
	if e != nil {
		t.Fatal(e)
	}
	current := string(plain)
	clear(plain)
	queryCredential(current, 200)
	disable := submit("disable", 3, "trade-api")
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], disable.ID, disable.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	queryCredential(current, 401)
	denied := submit("create", 0, "outside-api")
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], denied.ID, denied.Digest, unique(t)); e == nil {
		t.Fatal("real executor target grant escaped")
	}
	var requests int
	if e = f.db.QueryRow(`SELECT count(*) FROM keygate.passport_executions WHERE environment=$1 AND state='succeeded'`, f.c.environment).Scan(&requests); e != nil || requests != 4 {
		t.Fatal("unexpected real completed count", e)
	}
	// The only persisted delivery material is ciphertext, never a client_secret JSON field.
	raw, e = json.Marshal(out)
	if e != nil || bytes.Contains(raw, []byte(current)) || bytes.Contains(raw, []byte("clientSecret")) {
		t.Fatal("plaintext result leak")
	}
}
