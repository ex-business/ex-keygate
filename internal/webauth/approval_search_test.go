package webauth

import (
	"encoding/json"
	"ex-keygate/internal/storage"
	"testing"
)

func TestHTTPApprovalSearchQueries(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	alice := a.loginAs(t, "demo-approver-1")
	a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.CreateClient, ClientID: "search-http", Name: "搜索验收", ProfileID: "backend", ProfileVersion: 1})
	code, raw := a.business(t, owner, "GET", "/api/requests/search?q=search-http&view=applicant&limit=1", nil)
	var page storage.RequestSearchPage
	if code != 200 || json.Unmarshal(raw, &page) != nil || len(page.Items) != 1 {
		t.Fatal("申请搜索", code)
	}
	code, raw = a.business(t, alice, "GET", "/api/notifications/search?unread=true&limit=20", nil)
	var notices storage.NoticeSearchPage
	if code != 200 || json.Unmarshal(raw, &notices) != nil || len(notices.Items) != 1 {
		t.Fatal("通知搜索", code)
	}
	for _, path := range []string{"/api/requests/search?limit=0", "/api/requests/search?limit=1&limit=2", "/api/requests/search?unknown=x", "/api/requests/search?from=%zz", "/api/notifications/search?unread=1", "/api/notifications/search?view=all"} {
		if code, _ = a.business(t, owner, "GET", path, nil); code != 400 {
			t.Fatal("非法查询", path, code)
		}
	}
	if code, _ = a.business(t, businessActor{}, "GET", "/api/requests/search", nil); code != 401 {
		t.Fatal("匿名查询", code)
	}
}
