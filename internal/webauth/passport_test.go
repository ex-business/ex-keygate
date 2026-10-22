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

func TestHTTPPassportApprovalBoundary(t *testing.T) {
	var posts atomic.Int64
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(404)
			w.Write([]byte(`{"success":false,"code":"EXECUTOR_OPERATION_NOT_FOUND"}`))
			return
		}
		posts.Add(1)
		var b passport.Request
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": passport.Result{OperationID: b.OperationID, Operation: b.Operation, ClientID: b.ClientID, Revision: b.ExpectedRevision + 1}})
	}))
	defer remote.Close()
	adapter, e := passport.New(passport.Config{URL: remote.URL, ClientID: "executor", Secret: "epe_" + strings.Repeat("x", 43), AllowLoopbackHTTP: true})
	if e != nil {
		t.Fatal(e)
	}
	defer adapter.Close()
	a := setupFlowInitialized(t, true, "", nil, func(s *Service) {
		if e = s.ConfigurePassport(adapter); e != nil {
			t.Fatal(e)
		}
	})
	if e = a.service.ConfigurePassport(adapter); e == nil {
		t.Fatal("runtime reconfiguration")
	}
	owner := a.loginAs(t, "demo-requester")
	alice := a.loginAs(t, "demo-approver-1")
	bob := a.loginAs(t, "demo-approver-2")
	op := storage.ControlOperation{Kind: storage.PassportIntrospection, ClientID: "trade-api", ExpectedRevision: 1, Passport: &storage.PassportOperation{Operation: "disable"}}
	r := a.submitOperation(t, owner, op)
	executePath := "/api/requests/" + r.ID + "/execute"
	outcomePath := "/api/requests/" + r.ID + "/passport-result"
	if status, _ := a.business(t, owner, "POST", executePath, map[string]string{"digest": r.Digest}); status != 403 {
		t.Fatal("unapproved execution", status)
	}
	a.approveHTTP(t, []businessActor{alice, bob}, r)
	noCSRF := owner
	noCSRF.csrf = ""
	if status, _ := a.business(t, noCSRF, "POST", executePath, map[string]string{"digest": r.Digest}); status != 403 {
		t.Fatal("CSRF bypass", status)
	}
	if status, _ := a.business(t, owner, "POST", executePath, map[string]any{"digest": r.Digest, "expectedRevision": "2"}); status != 400 {
		t.Fatal("execution parameter override", status)
	}
	if status, _ := a.business(t, alice, "POST", executePath, map[string]string{"digest": r.Digest}); status != 403 {
		t.Fatal("nonapplicant execution", status)
	}
	if posts.Load() != 0 {
		t.Fatal("unauthorized remote dispatch")
	}
	if status, raw := a.business(t, owner, "POST", executePath, map[string]string{"digest": r.Digest}); status != 200 || !strings.Contains(string(raw), `"deliveryState":"not_required"`) {
		t.Fatal("missing execution delivery status", status)
	}
	a.executeHTTP(t, owner, r)
	if posts.Load() != 1 {
		t.Fatal("duplicate remote dispatch")
	}
	status, raw := a.business(t, owner, "GET", outcomePath, nil)
	var out storage.PassportOutcome
	if status != 200 || json.Unmarshal(raw, &out) != nil || out.State != "succeeded" || out.DeliveryState != "not_required" {
		t.Fatal("outcome unavailable", status)
	}
	if status, _ = a.business(t, alice, "GET", outcomePath, nil); status != 403 {
		t.Fatal("outcome authorization", status)
	}
	if status, _ = a.business(t, businessActor{}, "GET", outcomePath, nil); status != 401 {
		t.Fatal("anonymous outcome", status)
	}
}
