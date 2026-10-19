package webauth

import (
	"encoding/json"
	"ex-keygate/internal/storage"
	"testing"
	"time"
)

func TestHTTPAuditAndNewRootApproval(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	alice := a.loginAs(t, "demo-approver-1")
	bob := a.loginAs(t, "demo-approver-2")
	root := "replacement-" + hexToken()
	r := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.ProvisionRoot, ClientID: "root-management", RootID: root})
	if status, _ := a.business(t, owner, "POST", "/api/requests/"+r.ID+"/execute", map[string]string{"digest": r.Digest}); status == 200 {
		t.Fatal("未批准创建根")
	}
	a.approveHTTP(t, []businessActor{alice, bob}, r)
	a.executeHTTP(t, owner, r)
	a.executeHTTP(t, owner, r)
	if status, raw := a.business(t, owner, "GET", "/api/config", nil); status != 200 {
		t.Fatal(status, string(raw))
	} else {
		var c struct {
			RootID string `json:"rootId"`
		}
		if e := json.Unmarshal(raw, &c); e != nil || c.RootID != root {
			t.Fatal(c, e)
		}
	}
	filter := storage.AuditFilter{From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Minute), Limit: 100}
	if status, _ := a.business(t, alice, "POST", "/api/audit/query", filter); status != 403 {
		t.Fatal("审批人审计越权", status)
	}
	if status, _ := a.business(t, businessActor{}, "POST", "/api/audit/query", filter); status != 401 {
		t.Fatal("匿名审计", status)
	}
	status, raw := a.business(t, owner, "POST", "/api/audit/query", filter)
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	status, raw = a.business(t, owner, "POST", "/api/audit/exports", filter)
	if status != 201 {
		t.Fatal(status, string(raw))
	}
	var out storage.AuditExport
	if e := json.Unmarshal(raw, &out); e != nil || out.State != "ready" {
		t.Fatal(out, e)
	}
	if status, raw = a.business(t, owner, "GET", "/api/audit/exports/"+out.ID, nil); status != 200 {
		t.Fatal(status, string(raw))
	}
	if status, _ = a.business(t, alice, "GET", "/api/audit/exports/"+out.ID, nil); status == 200 {
		t.Fatal("其他人下载")
	}
}
