package webauth

import (
	"encoding/json"
	"ex-keygate/internal/storage"
	"testing"
)

func TestHTTPApprovalInboxAndWithdraw(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	alice := a.loginAs(t, "demo-approver-1")
	r := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.CreateClient, ClientID: "notice-http", Name: "通知测试", ProfileID: "backend", ProfileVersion: 1})
	status, raw := a.business(t, alice, "GET", "/api/notifications", nil)
	var notices []storage.ApprovalNotification
	if status != 200 || json.Unmarshal(raw, &notices) != nil || len(notices) != 1 {
		t.Fatal("收件箱", status)
	}
	id := notices[0].ID
	if status, _ = a.business(t, owner, "POST", "/api/notifications/"+id+"/read", map[string]string{}); status != 403 {
		t.Fatal("越权已读", status)
	}
	if status, _ = a.business(t, alice, "POST", "/api/notifications/"+id+"/read", map[string]string{}); status != 204 {
		t.Fatal("本人已读", status)
	}
	body := map[string]string{"digest": r.Digest, "reason": "取消本次申请"}
	if status, _ = a.business(t, alice, "POST", "/api/requests/"+r.ID+"/withdraw", body); status != 403 {
		t.Fatal("代撤回", status)
	}
	noCSRF := owner
	noCSRF.csrf = ""
	if status, _ = a.business(t, noCSRF, "POST", "/api/requests/"+r.ID+"/withdraw", body); status != 403 {
		t.Fatal("未校验CSRF", status)
	}
	if status, _ = a.business(t, owner, "POST", "/api/requests/"+r.ID+"/withdraw", body); status != 200 {
		t.Fatal("撤回", status)
	}
	if status, _ = a.business(t, alice, "POST", "/api/requests/"+r.ID+"/votes", map[string]any{"digest": r.Digest, "accept": true}); status != 409 {
		t.Fatal("撤回后投票", status)
	}
}
