package storage

import (
	"context"
	"errors"
	"ex-keygate/internal/access"
	"sync"
	"testing"
)

func opsAdmin(t *testing.T, f controlFixture) {
	t.Helper()
	if _, e := f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,'policy_admin','')`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
}
func TestNotificationOperationsResendAndHistory(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	r := submitClient(t, f, "ops-retry")
	opsAdmin(t, f)
	if _, e := f.c.NotificationOperations(ctx, f.tokens[1], "", 0); !errors.Is(e, ErrDenied) {
		t.Fatal("普通审批人查看运维", e)
	}
	grantAuditor(t, f, 4, "one")
	if _, e := f.c.NotificationOperations(ctx, f.tokens[4], "", 0); !errors.Is(e, ErrDenied) {
		t.Fatal("局部审计越权", e)
	}
	grantAuditor(t, f, 2, "")
	var id string
	if e := f.db.QueryRow(`SELECT id FROM keygate.approval_notifications WHERE environment=$1 AND request_id=$2 ORDER BY id LIMIT 1`, f.c.environment, r.ID).Scan(&id); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`UPDATE keygate.approval_notifications SET state='obsolete' WHERE environment=$1 AND id<>$2`, f.c.environment, id); e != nil {
		t.Fatal(e)
	}
	sink := &approvalSink{failure: true}
	for i := 0; i < 5; i++ {
		f.db.Exec(`UPDATE keygate.approval_notifications SET next_attempt=clock_timestamp() WHERE environment=$1 AND id=$2`, f.c.environment, id)
		if _, e := f.c.DispatchApprovalNotification(ctx, sink); e != nil {
			t.Fatal(e)
		}
	}
	before, e := f.c.NotificationDeliveryRecords(ctx, f.tokens[2], id)
	if e != nil || len(before) != 5 {
		t.Fatal("尝试记录", e, len(before))
	}
	if e = f.c.ResendApprovalNotification(ctx, f.tokens[2], id, r.Digest, "只读审计不能重发", unique(t), 0); !errors.Is(e, ErrDenied) {
		t.Fatal("审计员重发", e)
	}
	// 两个操作员请求相同预期轮次，只允许一个理由真正增加预算。
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	for _, reason := range []string{"人工重发原因一", "人工重发原因二"} {
		go func(reason string) {
			defer wg.Done()
			results <- f.c.ResendApprovalNotification(ctx, f.tokens[0], id, r.Digest, reason, unique(t), 0)
		}(reason)
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("并发重发预算", success)
	}
	records, e := f.c.NotificationDeliveryRecords(ctx, f.tokens[0], id)
	if e != nil || len(records) != 6 || records[5].Outcome != "rescheduled" {
		t.Fatal("重发记录", e)
	}
	if e = f.c.ResendApprovalNotification(ctx, f.tokens[0], id, r.Digest, records[5].Reason, unique(t), 0); e != nil {
		t.Fatal("同请求不幂等", e)
	}
	sink.failure = false
	if _, e = f.c.DispatchApprovalNotification(ctx, sink); e != nil {
		t.Fatal(e)
	}
	if sink.calls[len(sink.calls)-1].ID != id || sink.calls[len(sink.calls)-1].Resends != 1 {
		t.Fatal("标识或轮次变化")
	}
	records, e = f.c.NotificationDeliveryRecords(ctx, f.tokens[0], id)
	if e != nil || len(records) != 7 || records[6].Outcome != "sent" {
		t.Fatal("新轮次记录", e)
	}
	if e = f.c.ResendApprovalNotification(ctx, f.tokens[0], id, r.Digest, "不能重发成功任务", unique(t), 1); !errors.Is(e, ErrConflict) {
		t.Fatal("重发成功任务", e)
	}
	if _, e = f.c.NotificationOperations(ctx, f.tokens[0], "bad", 0); !errors.Is(e, ErrInvalid) {
		t.Fatal("非法筛选", e)
	}
	// 失败状态也不能绕过冷却和人工轮次硬上限，测试仅调整一次性库的时间。
	f.db.Exec(`UPDATE keygate.approval_notifications SET state='failed',attempts=5 WHERE environment=$1 AND id=$2`, f.c.environment, id)
	if e = f.c.ResendApprovalNotification(ctx, f.tokens[0], id, r.Digest, "冷却期应拒绝", unique(t), 1); !errors.Is(e, ErrConflict) {
		t.Fatal("冷却未限制", e)
	}
	for round := 1; round < 3; round++ {
		f.db.Exec(`UPDATE keygate.approval_notifications SET state='failed',attempts=5,last_resend_at=clock_timestamp()-interval '61 seconds' WHERE environment=$1 AND id=$2`, f.c.environment, id)
		if e = f.c.ResendApprovalNotification(ctx, f.tokens[0], id, r.Digest, "再次受控重试", unique(t), round); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.c.ResendApprovalNotification(ctx, f.tokens[0], id, r.Digest, "超过人工上限", unique(t), 3); !errors.Is(e, ErrInvalid) {
		t.Fatal("重发无上限", e)
	}
	// 撤权后原运维入口立即拒绝。
	f.db.Exec(`UPDATE keygate.role_grants SET enabled=false WHERE environment=$1 AND principal_id=$2 AND role=$3`, f.c.environment, f.bootstrap.Principals[0].ID, access.PolicyAdmin)
	if _, e = f.c.NotificationDeliveryRecords(ctx, f.tokens[0], id); !errors.Is(e, ErrDenied) {
		t.Fatal("撤权后读取记录", e)
	}
}
func TestNotificationOperationsInvalidationAndAlerts(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	opsAdmin(t, f)
	r := submitClient(t, f, "ops-alert")
	f.db.Exec(`UPDATE keygate.approval_notifications SET created_at=clock_timestamp()-interval '6 minutes' WHERE environment=$1`, f.c.environment)
	if e := f.c.CollectApprovalNotifications(ctx); e != nil {
		t.Fatal(e)
	}
	out, e := f.c.NotificationOperations(ctx, f.tokens[0], "pending", 0)
	if e != nil || len(out.Items) == 0 {
		t.Fatal(e)
	}
	active := false
	for _, a := range out.Alerts {
		if a.Code == "backlog" {
			active = a.Active
		}
	}
	if !active {
		t.Fatal("积压未告警")
	}
	id := out.Items[0].ID
	f.db.Exec(`UPDATE keygate.approval_notifications SET state='failed',attempts=5 WHERE environment=$1 AND id=$2`, f.c.environment, id)
	if _, e = f.c.WithdrawRequest(ctx, f.tokens[0], r.ID, r.Digest, "撤回使旧待办失效", unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = f.c.ResendApprovalNotification(ctx, f.tokens[0], id, r.Digest, "不允许恢复旧提醒", unique(t), 0); !errors.Is(e, ErrConflict) {
		t.Fatal("失效任务可重发", e)
	}
	if e = f.c.CollectApprovalNotifications(ctx); e != nil {
		t.Fatal(e)
	}
	out, e = f.c.NotificationOperations(ctx, f.tokens[0], "", 0)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range out.Alerts {
		if a.Code == "backlog" && a.Active {
			t.Fatal("积压恢复未清除")
		}
	}
}
