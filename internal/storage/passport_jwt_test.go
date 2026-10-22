package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"ex-keygate/internal/config"
	"ex-keygate/internal/passport"
)

func grantJWTPolicyAdmin(t *testing.T, f controlFixture) {
	t.Helper()
	if _, e := f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role) VALUES($1,$2,'policy_admin') ON CONFLICT DO NOTHING`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
}
func jwtOperation(operation string, revision uint64) ControlOperation {
	return ControlOperation{Kind: PassportJWTKind, ClientID: PassportJWTScope, ExpectedRevision: revision, JWT: &PassportJWT{Operation: operation, Kid: "next", Reason: "approved synthetic JWT lifecycle"}}
}
func TestPassportJWTApprovalBindingAndRecovery(t *testing.T) {
	for _, action := range []string{"publish", "activate", "retire", "revoke"} {
		for _, fault := range []string{"none", "lost-response", "query-failure"} {
			t.Run(action+"/"+fault, func(t *testing.T) {
				ctx := context.Background()
				f := newControlFixture(t)
				var calls atomic.Int64
				var queries atomic.Int64
				var committed atomic.Bool
				var fail atomic.Bool
				fail.Store(true)
				var request passport.JWTRequest
				remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "GET" {
						queries.Add(1)
						if fault == "query-failure" && fail.Swap(false) {
							w.WriteHeader(503)
							return
						}
						if !committed.Load() {
							w.WriteHeader(404)
							w.Write([]byte(`{"success":false,"code":"EXECUTOR_OPERATION_NOT_FOUND"}`))
							return
						}
						json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": passport.Result{OperationID: request.OperationID, ApprovalDigest: request.ApprovalDigest, Operation: request.Operation, Kid: request.Kid, Revision: request.ExpectedRevision + 1, RequestHash: request.Hash(), Replayed: true}})
						return
					}
					calls.Add(1)
					if json.NewDecoder(r.Body).Decode(&request) != nil {
						w.WriteHeader(400)
						return
					}
					committed.Store(true)
					if fault == "lost-response" && fail.Swap(false) {
						conn, _, e := w.(http.Hijacker).Hijack()
						if e == nil {
							conn.Close()
						}
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": passport.Result{OperationID: request.OperationID, ApprovalDigest: request.ApprovalDigest, Operation: request.Operation, Kid: request.Kid, Revision: request.ExpectedRevision + 1, RequestHash: request.Hash()}})
				}))
				defer remote.Close()
				adapter, e := passport.New(passport.Config{URL: remote.URL, ClientID: "jwt-executor", Secret: "epe_" + strings.Repeat("j", 43), AllowLoopbackHTTP: true})
				if e != nil {
					t.Fatal(e)
				}
				defer adapter.Close()
				if e = f.c.ConfigurePassportJWT(adapter); e != nil {
					t.Fatal(e)
				}
				op := jwtOperation(action, 7)
				if action == "publish" {
					pub, _, _ := ed25519.GenerateKey(rand.Reader)
					op.JWT.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
				}
				if _, e = f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t)); !errors.Is(e, ErrDenied) {
					t.Fatal("requester without policy admin managed global JWT", e)
				}
				grantJWTPolicyAdmin(t, f)
				idem := unique(t)
				r, e := f.c.Submit(ctx, f.tokens[0], op, idem, unique(t))
				if e != nil {
					t.Fatal(e)
				}
				again, e := f.c.Submit(ctx, f.tokens[0], op, idem, unique(t))
				if e != nil || again.ID != r.ID {
					t.Fatal("submission idempotency", e)
				}
				var manifest controlManifest
				if json.Unmarshal(r.Manifest, &manifest) != nil || manifest.Operation.JWT.OperationID == "" || manifest.Operation.JWT.EndpointBinding != adapter.EndpointBinding() || manifest.ProviderAdmin == nil {
					t.Fatal("approval lacks fixed executor or admin snapshot")
				}
				if action == "publish" && manifest.Operation.JWT.PublicKeyFingerprint == "" {
					t.Fatal("public material fingerprint missing")
				}
				if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); !errors.Is(e, ErrDenied) {
					t.Fatal("executed without approvals", e)
				}
				if calls.Load() != 0 || queries.Load() != 0 {
					t.Fatal("remote contacted without approval")
				}
				approveControl(t, f, r)
				if e = f.c.ExecuteRequested(ctx, f.tokens[1], r.ID, r.Digest, unique(t)); !errors.Is(e, ErrDenied) {
					t.Fatal("approver bypassed applicant boundary", e)
				}
				e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t))
				if fault == "none" && e != nil {
					t.Fatal(e)
				}
				if fault != "none" && e == nil {
					t.Fatal("failure not reported")
				}
				restarted, e := NewDevelopmentControl(config.Test, f.c.environment, f.profile, f.c.store)
				if e != nil {
					t.Fatal(e)
				}
				restarted.ConfigurePassportJWT(adapter)
				var wg sync.WaitGroup
				errs := make(chan error, 6)
				for range 6 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						errs <- restarted.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t))
					}()
				}
				wg.Wait()
				close(errs)
				for e := range errs {
					if e != nil {
						t.Fatal(e)
					}
				}
				if calls.Load() != 1 {
					t.Fatal("JWT action repeated", calls.Load())
				}
				if request.ApprovalDigest != r.Digest || request.OperationID != manifest.Operation.JWT.OperationID || request.ExpectedRevision != 7 || request.Reason != op.JWT.Reason || request.PublicKey != op.JWT.PublicKey {
					t.Fatal("unapproved request substituted")
				}
				out, e := restarted.PassportOutcome(ctx, f.tokens[0], r.ID)
				if e != nil || out.State != "succeeded" || out.DeliveryState != "not_required" || out.CommittedRevision == nil || *out.CommittedRevision != 8 || len(out.Ciphertext) != 0 {
					t.Fatal("JWT outcome mismatch", e)
				}
				if _, e = restarted.PassportOutcome(ctx, f.tokens[1], r.ID); !errors.Is(e, ErrDenied) {
					t.Fatal("outcome authorization", e)
				}
			})
		}
	}
}
func TestPassportJWTRevocationStillRequiresCurrentGlobalAuthority(t *testing.T) {
	for _, scenario := range []string{"scoped-requester", "scoped-approvers", "policy-admin-revoked", "vote-revoked", "digest-replaced"} {
		t.Run(scenario, func(t *testing.T) {
			f := newControlFixture(t)
			ctx := context.Background()
			var calls atomic.Int64
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
			defer remote.Close()
			adapter, _ := passport.New(passport.Config{URL: remote.URL, ClientID: "jwt", Secret: "epe_" + strings.Repeat("j", 43), AllowLoopbackHTTP: true})
			defer adapter.Close()
			f.c.ConfigurePassportJWT(adapter)
			grantJWTPolicyAdmin(t, f)
			op := jwtOperation("revoke", 5)
			if scenario == "scoped-requester" {
				f.db.Exec(`UPDATE keygate.role_grants SET client_id=$3 WHERE environment=$1 AND principal_id=$2 AND role='requester'`, f.c.environment, f.bootstrap.Principals[0].ID, PassportJWTScope)
				if _, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t)); !errors.Is(e, ErrDenied) {
					t.Fatal("scoped requester became global issuer operator", e)
				}
				return
			}
			if scenario == "scoped-approvers" {
				f.db.Exec(`UPDATE keygate.role_grants SET client_id=$2 WHERE environment=$1 AND role='approver'`, f.c.environment, PassportJWTScope)
				if _, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t)); !errors.Is(e, ErrDenied) {
					t.Fatal("scoped approvers became global issuer approvers", e)
				}
				return
			}
			r, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
			if e != nil {
				t.Fatal(e)
			}
			approveControl(t, f, r)
			digest := r.Digest
			switch scenario {
			case "policy-admin-revoked":
				f.db.Exec(`UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND role='policy_admin'`, f.c.environment, f.bootstrap.Principals[0].ID)
			case "vote-revoked":
				f.db.Exec(`UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND role='approver'`, f.c.environment, f.bootstrap.Principals[1].ID)
			case "digest-replaced":
				digest = strings.Repeat("b", 64)
			}
			if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, digest, unique(t)); e == nil {
				t.Fatal("stale emergency authority was accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("emergency revocation bypassed approval freshness")
			}
		})
	}
}
