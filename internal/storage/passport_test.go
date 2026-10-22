package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ex-keygate/internal/config"
	"ex-keygate/internal/passport"
)

func passportRecipient(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	return key, base64.RawStdEncoding.EncodeToString(der), digestBytes(der)
}
func TestPassportApprovedExecutionAndRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "response-lost", "timeout-after-commit", "query-unavailable", "post-not-committed", "db-commit-lost", "revoked-before-send", "revoked-after-commit"} {
		t.Run(scenario, func(t *testing.T) {
			f := newControlFixture(t)
			ctx := context.Background()
			recipient, encoded, fp := passportRecipient(t)
			var posts atomic.Int64
			var queries atomic.Int64
			var request passport.Request
			var committed atomic.Bool
			var drop atomic.Bool
			drop.Store(true)
			var killDB *sql.DB
			if scenario == "db-commit-lost" {
				var err error
				killDB, err = sql.Open("pgx", os.Getenv("KEYGATE_TEST_DATABASE_URL"))
				if err != nil {
					t.Fatal(err)
				}
				defer killDB.Close()
			}
			secret := "epi_" + strings.Repeat("s", 43)
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					queries.Add(1)
					if scenario == "query-unavailable" && drop.Swap(false) {
						w.WriteHeader(503)
						return
					}
					if !committed.Load() {
						w.WriteHeader(404)
						w.Write([]byte(`{"success":false,"code":"EXECUTOR_OPERATION_NOT_FOUND"}`))
						return
					}
					result := passport.Result{OperationID: request.OperationID, Operation: request.Operation, ClientID: request.ClientID, Revision: 2, RequestHash: request.Hash(), Replayed: true}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": result})
					return
				}
				posts.Add(1)
				if e := json.NewDecoder(r.Body).Decode(&request); e != nil {
					t.Error(e)
					return
				}
				if scenario == "post-not-committed" && drop.Swap(false) {
					w.WriteHeader(503)
					return
				}
				committed.Store(true)
				if scenario == "timeout-after-commit" && drop.Swap(false) {
					<-r.Context().Done()
					return
				}
				if (scenario == "response-lost" || scenario == "revoked-after-commit") && drop.Swap(false) {
					conn, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						conn.Close()
					}
					return
				}
				if scenario == "db-commit-lost" && drop.Swap(false) {
					killDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='passport-execution-loss' AND pid<>pg_backend_pid()`)
				}
				result := passport.Result{OperationID: request.OperationID, Operation: request.Operation, ClientID: request.ClientID, Revision: 2, ClientSecret: secret}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": result})
			}))
			defer remote.Close()
			adapter, e := passport.New(passport.Config{URL: remote.URL, ClientID: "executor", Secret: "epe_" + strings.Repeat("e", 43), AllowLoopbackHTTP: true})
			if e != nil {
				t.Fatal(e)
			}
			defer adapter.Close()
			if e = f.c.ConfigurePassport(adapter); e != nil {
				t.Fatal(e)
			}
			op := ControlOperation{Kind: PassportIntrospection, ClientID: "trade-api", ExpectedRevision: 1, Passport: &PassportOperation{Operation: "rotate", RecipientPublicKey: encoded, RecipientFingerprint: fp}}
			idem := unique(t)
			record, e := f.c.Submit(ctx, f.tokens[0], op, idem, unique(t))
			if e != nil {
				t.Fatal(e)
			}
			again, e := f.c.Submit(ctx, f.tokens[0], op, idem, unique(t))
			if e != nil || again.ID != record.ID {
				t.Fatal("submission idempotency", e)
			}
			if e = f.c.ExecuteRequested(ctx, f.tokens[0], record.ID, record.Digest, unique(t)); !errors.Is(e, ErrDenied) {
				t.Fatal("unapproved dispatch", e)
			}
			if posts.Load() != 0 || queries.Load() != 0 {
				t.Fatal("remote contacted before approval")
			}
			approveControl(t, f, record)
			if e = f.c.ExecuteRequested(ctx, f.tokens[1], record.ID, record.Digest, unique(t)); !errors.Is(e, ErrDenied) {
				t.Fatal("nonapplicant execute", e)
			}
			if e = f.c.ExecuteRequested(ctx, f.tokens[0], record.ID, strings.Repeat("b", 64), unique(t)); !errors.Is(e, ErrConflict) {
				t.Fatal("digest substitution", e)
			}
			if scenario == "revoked-before-send" {
				// Reserve while valid; subsequent revocation must never allow a new POST.
				if _, e = f.c.reservePassport(ctx, f.tokens[0], record.ID, record.Digest, unique(t)); e != nil {
					t.Fatal(e)
				}
				revokePassportVote(t, f, record.ID)
			}
			if scenario == "db-commit-lost" {
				// A dedicated pool labels only the in-flight executor transaction; the fake
				// remote terminates it after committing its operation.
				f.db.SetMaxOpenConns(1)
				if _, e = f.db.Exec(`SET application_name='passport-execution-loss'`); e != nil {
					t.Fatal(e)
				}

			}
			firstContext := ctx
			cancel := func() {}
			if scenario == "timeout-after-commit" {
				firstContext, cancel = context.WithTimeout(ctx, 750*time.Millisecond)
			}
			e = f.c.ExecuteRequested(firstContext, f.tokens[0], record.ID, record.Digest, unique(t))
			cancel()
			if scenario == "success" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("fault not reported")
			}
			if scenario == "revoked-before-send" {
				if posts.Load() != 0 {
					t.Fatal("revoked POST")
				}
				return
			}
			if scenario == "revoked-after-commit" {
				revokePassportVote(t, f, record.ID)
			}
			// A fresh control instance proves that stable identity comes from the durable
			// manifest/reservation rather than an in-memory retry cache.
			restarted, e := NewDevelopmentControl(config.Test, f.c.environment, f.c.profile, f.c.store)
			if e != nil {
				t.Fatal(e)
			}
			if e = restarted.ConfigurePassport(adapter); e != nil {
				t.Fatal(e)
			}
			var wg sync.WaitGroup
			errs := make(chan error, 6)
			for range 6 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs <- restarted.ExecuteRequested(ctx, f.tokens[0], record.ID, record.Digest, unique(t))
				}()
			}
			wg.Wait()
			close(errs)
			for e := range errs {
				if e != nil {
					t.Fatal(e)
				}
			}
			wantPosts := int64(1)
			if scenario == "post-not-committed" {
				wantPosts = 2
			}
			if posts.Load() != wantPosts {
				t.Fatalf("POSTs=%d want %d", posts.Load(), wantPosts)
			}
			out, e := restarted.PassportOutcome(ctx, f.tokens[0], record.ID)
			if e != nil || out.State != "succeeded" || out.CommittedRevision == nil || *out.CommittedRevision != 2 {
				t.Fatal("missing committed outcome", e)
			}
			if request.OperationID != out.OperationID {
				t.Fatal("operation changed")
			}
			if scenario == "response-lost" || scenario == "timeout-after-commit" || scenario == "revoked-after-commit" || scenario == "db-commit-lost" {
				if out.DeliveryState != "unavailable" || len(out.Ciphertext) != 0 {
					t.Fatal("invented secret recovery")
				}
			} else {
				plain, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, recipient, out.Ciphertext, out.OAEPLabel)
				if e != nil || string(plain) != secret {
					t.Fatal("recipient delivery failed", e)
				}
				clear(plain)
				if _, e = rsa.DecryptOAEP(sha256.New(), rand.Reader, recipient, out.Ciphertext, []byte("other approval")); e == nil {
					t.Fatal("unbound ciphertext")
				}
			}
			if _, e = restarted.PassportOutcome(ctx, f.tokens[1], record.ID); !errors.Is(e, ErrDenied) {
				t.Fatal("outcome requester restriction", e)
			}
			var binding controlManifest
			if e = json.Unmarshal(record.Manifest, &binding); e != nil {
				t.Fatal(e)
			}
			if binding.Operation.Passport.OperationID != out.OperationID || binding.Operation.Passport.EndpointBinding != adapter.EndpointBinding() {
				t.Fatal("approval lacked operation binding")
			}
			var count int
			if e = f.db.QueryRow(`SELECT count(*) FROM keygate.control_executions WHERE environment=$1 AND request_id=$2`, f.c.environment, record.ID).Scan(&count); e != nil || count != 1 {
				t.Fatal("duplicate execution", e)
			}
		})
	}
}
func revokePassportVote(t *testing.T, f controlFixture, id string) {
	t.Helper()
	if _, e := f.db.Exec(`UPDATE keygate.role_grants SET revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND role='approver'`, f.c.environment, f.bootstrap.Principals[1].ID); e != nil {
		t.Fatal(e)
	}
}
