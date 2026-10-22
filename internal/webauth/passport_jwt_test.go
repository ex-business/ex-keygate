package webauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"ex-keygate/internal/passport"
	"ex-keygate/internal/storage"
)

func TestHTTPPassportJWTApprovalAndState(t *testing.T) {
	var calls atomic.Int64
	var approvedDigest string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/management/v1/jwt-keys" {
			json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": map[string]any{"revision": 5, "currentKid": "old", "keys": []any{}}})
			return
		}
		if r.Method == "GET" {
			w.WriteHeader(404)
			w.Write([]byte(`{"success":false,"code":"EXECUTOR_OPERATION_NOT_FOUND"}`))
			return
		}
		calls.Add(1)
		var b passport.JWTRequest
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			w.WriteHeader(400)
			return
		}
		approvedDigest = b.ApprovalDigest
		json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": passport.Result{OperationID: b.OperationID, ApprovalDigest: b.ApprovalDigest, Operation: b.Operation, Kid: b.Kid, Revision: 6, RequestHash: b.Hash()}})
	}))
	defer remote.Close()
	adapter, e := passport.New(passport.Config{URL: remote.URL, ClientID: "jwt", Secret: "epe_" + strings.Repeat("j", 43), AllowLoopbackHTTP: true})
	if e != nil {
		t.Fatal(e)
	}
	defer adapter.Close()
	a := setupFlowInitialized(t, true, "", nil, func(s *Service) {
		if e = s.ConfigurePassportJWT(adapter); e != nil {
			t.Fatal(e)
		}
	})
	owner := a.loginAs(t, "demo-requester")
	alice := a.loginAs(t, "demo-approver-1")
	bob := a.loginAs(t, "demo-approver-2")
	if status, _ := a.business(t, owner, "GET", "/api/passport/jwt-keys", nil); status != 200 {
		t.Fatal("global admin state query", status)
	}
	if status, _ := a.business(t, alice, "GET", "/api/passport/jwt-keys", nil); status != 403 {
		t.Fatal("approver gained global JWT management read", status)
	}
	op := storage.ControlOperation{Kind: storage.PassportJWTKind, ClientID: storage.PassportJWTScope, ExpectedRevision: 5, JWT: &storage.PassportJWT{Operation: "revoke", Kid: "old", Reason: "confirmed incident requires approval"}}
	if status, _ := a.business(t, alice, "POST", "/api/requests", op); status != 403 {
		t.Fatal("approver created JWT request", status)
	}
	r := a.submitOperation(t, owner, op)
	path := "/api/requests/" + r.ID + "/execute"
	if status, _ := a.business(t, owner, "POST", path, map[string]string{"digest": r.Digest}); status != 403 {
		t.Fatal("emergency bypassed M-of-N", status)
	}
	a.approveHTTP(t, []businessActor{alice, bob}, r)
	noCSRF := owner
	noCSRF.csrf = ""
	if status, _ := a.business(t, noCSRF, "POST", path, map[string]string{"digest": r.Digest}); status != 403 {
		t.Fatal("CSRF bypass", status)
	}
	if status, _ := a.business(t, owner, "POST", path, map[string]any{"digest": r.Digest, "kid": "another"}); status != 400 {
		t.Fatal("execution override accepted", status)
	}
	if calls.Load() != 0 {
		t.Fatal("remote mutation before authorized execution")
	}
	status, raw := a.business(t, owner, "POST", path, map[string]string{"digest": r.Digest})
	if status != 200 || !strings.Contains(string(raw), `"deliveryState":"not_required"`) {
		t.Fatal("JWT execute response", status)
	}
	if approvedDigest != r.Digest {
		t.Fatal("approval digest missing from remote action")
	}
	a.executeHTTP(t, owner, r)
	if calls.Load() != 1 {
		t.Fatal("replayed JWT mutation")
	}
	if status, _ = a.business(t, alice, "GET", "/api/requests/"+r.ID+"/passport-result", nil); status != 403 {
		t.Fatal("cross-user result query", status)
	}
}
