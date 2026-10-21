package webauth

import (
	"encoding/json"
	"ex-keygate/internal/storage"
	"testing"
)

func TestHTTPNotificationOperationsPermissions(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	alice := a.loginAs(t, "demo-approver-1")
	r := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.CreateClient, ClientID: "ops-http", Name: "通知运维测试", ProfileID: "backend", ProfileVersion: 1})
	if status, _ := a.business(t, alice, "GET", "/api/notification-operations", nil); status != 403 {
		t.Fatal("普通人员访问运维", status)
	}
	for _, query := range []string{"?state=failed&state=pending", "?offset=0&extra=x", "?state=%zz", "?"} {
		if code, _ := a.business(t, owner, "GET", "/api/notification-operations"+query, nil); code != 400 {
			t.Fatal("非法查询未拒绝", query, code)
		}
	}
	status, raw := a.business(t, owner, "GET", "/api/notification-operations?state=pending", nil)
	var out storage.NotificationOperations
	if status != 200 || json.Unmarshal(raw, &out) != nil || len(out.Items) == 0 || !out.CanResend {
		t.Fatal("管理员运维", status)
	}
	n := out.Items[0]
	if status, _ = a.business(t, owner, "GET", "/api/notification-operations?offset=-1", nil); status != 400 {
		t.Fatal("非法分页", status)
	}
	if status, _ = a.business(t, alice, "GET", "/api/notification-operations/"+n.ID+"/records", nil); status != 403 {
		t.Fatal("投递记录越权", status)
	}
	body := map[string]any{"digest": r.Digest, "reason": "测试重发通知", "expectedRound": 0}
	noCSRF := owner
	noCSRF.csrf = ""
	if status, _ = a.business(t, noCSRF, "POST", "/api/notification-operations/"+n.ID+"/resend", body); status != 403 {
		t.Fatal("缺少CSRF仍重发", status)
	}
	if status, _ = a.business(t, owner, "POST", "/api/notification-operations/"+n.ID+"/resend", body); status != 409 {
		t.Fatal("等待任务被重发", status)
	}
	delete(body, "expectedRound")
	if status, _ = a.business(t, owner, "POST", "/api/notification-operations/"+n.ID+"/resend", body); status != 400 {
		t.Fatal("未冻结轮次", status)
	}
}
