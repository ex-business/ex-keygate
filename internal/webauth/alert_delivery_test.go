package webauth

import (
	"context"
	"ex-keygate/internal/storage"
	"testing"
)

func TestHTTPAlertDeliveryPermissionsAndCSRF(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	alice := a.loginAs(t, "demo-approver-1")
	if status, _ := a.business(t, owner, "GET", "/api/alert-deliveries", nil); status != 200 {
		t.Fatal("管理员读取", status)
	}
	if status, _ := a.business(t, alice, "GET", "/api/alert-deliveries", nil); status != 403 {
		t.Fatal("普通审批人越权", status)
	}
	body := map[string]any{"code": "monitor_stale", "reason": "受控测试维护窗口", "seconds": 900}
	missing := owner
	missing.csrf = ""
	if status, _ := a.business(t, missing, "POST", "/api/alert-silences", body); status != 403 {
		t.Fatal("静默绕过CSRF", status)
	}
	if status, _ := a.business(t, alice, "POST", "/api/alert-silences", body); status != 403 {
		t.Fatal("静默越权", status)
	}
	if status, _ := a.business(t, owner, "POST", "/api/alert-silences", map[string]any{"code": "monitor_stale", "reason": "测试缺少期限"}); status != 400 {
		t.Fatal("静默缺少期限", status)
	}
	if e := a.service.ConfigureAlertDelivery(context.Background(), map[string]storage.AlertBinding{}); e == nil {
		t.Fatal("启动后改路由")
	}
}
