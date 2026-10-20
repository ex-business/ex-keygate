package storage

import (
	"context"
	"errors"
	"ex-keygate/internal/manifest"
	"sync"
	"testing"
	"time"
)

func TestApprovalInboxHandoffAndWithdrawal(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	completeNative(t, f, 0, "management", 1)
	completeNative(t, f, 1, "management", 1)
	completeNative(t, f, 2, "management", 1)
	r := submitClient(t, f, "notice-handoff")
	one, e := f.c.ApprovalNotifications(ctx, f.tokens[1])
	if e != nil || len(one) != 1 || one[0].Kind != "approval_turn" {
		t.Fatal("首位审批人通知", e)
	}
	two, e := f.c.ApprovalNotifications(ctx, f.tokens[2])
	if e != nil || len(two) != 0 {
		t.Fatal("提前通知下一位", e)
	}
	if e = f.c.ReadApprovalNotification(ctx, f.tokens[2], one[0].ID); !errors.Is(e, ErrDenied) {
		t.Fatal("越权已读", e)
	}
	if e = f.c.ReadApprovalNotification(ctx, f.tokens[1], one[0].ID); e != nil {
		t.Fatal(e)
	}
	completeNative(t, f, 1, r.ID, 2)
	if _, e = f.c.Vote(ctx, f.tokens[1], r.ID, r.Digest, true, unique(t)); e != nil {
		t.Fatal(e)
	}
	two, e = f.c.ApprovalNotifications(ctx, f.tokens[2])
	if e != nil || len(two) != 1 || two[0].Kind != "approval_turn" {
		t.Fatal("下一位交接通知", e)
	}
	if _, e = f.c.WithdrawRequest(ctx, f.tokens[1], r.ID, r.Digest, "不允许代为撤回", unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("他人撤回", e)
	}
	withdrawn, e := f.c.WithdrawRequest(ctx, f.tokens[0], r.ID, r.Digest, "取消本次测试申请", unique(t))
	if e != nil || withdrawn.Decision != "cancelled" || withdrawn.WithdrawnBy == "" || withdrawn.WithdrawnAt == nil {
		t.Fatal("撤回状态", e)
	}
	if _, e = f.c.WithdrawRequest(ctx, f.tokens[0], r.ID, r.Digest, "取消本次测试申请", unique(t)); e != nil {
		t.Fatal("重复撤回不幂等", e)
	}
	if _, e = f.c.Vote(ctx, f.tokens[2], r.ID, r.Digest, true, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("撤回后仍投票", e)
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e == nil {
		t.Fatal("撤回后仍执行")
	}
	var votes int
	if e = f.db.QueryRow(`SELECT count(*) FROM keygate.control_votes WHERE environment=$1 AND request_id=$2`, f.c.environment, r.ID).Scan(&votes); e != nil || votes != 1 {
		t.Fatal("撤回删除历史票", e)
	}
	var obsolete int
	if e = f.db.QueryRow(`SELECT count(*) FROM keygate.approval_notifications WHERE environment=$1 AND request_id=$2 AND kind='approval_turn' AND state='obsolete'`, f.c.environment, r.ID).Scan(&obsolete); e != nil || obsolete != 2 {
		t.Fatal("旧提醒未失效", e)
	}
}

// 只在一次性测试库调整完整规范清单及摘要，生产申请期限仍由服务固定生成。
func retimeApproval(t *testing.T, f controlFixture, id string, remaining time.Duration) {
	t.Helper()
	ctx := context.Background()
	tx, e := f.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	r, m, e := f.c.loadRequest(ctx, tx, id)
	if e != nil {
		t.Fatal(e)
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		t.Fatal(e)
	}
	expires := now.Add(remaining).UTC().Truncate(time.Millisecond)
	m.Created = expires.Add(-5 * time.Minute).Format("2006-01-02T15:04:05.000Z")
	m.Expires = expires.Format("2006-01-02T15:04:05.000Z")
	raw, e := manifest.Canonical(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET manifest=$3,digest=$4,expires_at=$5,notice_terminal=false,notice_next_scan=clock_timestamp()-interval '1 second' WHERE environment=$1 AND request_id=$2`, f.c.environment, r.ID, raw, digestBytes(raw), expires); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
}
func TestApprovalDueAndExpiredNoticesDeduplicate(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	r := submitClient(t, f, "notice-deadline")
	retimeApproval(t, f, r.ID, 30*time.Second)
	for i := 0; i < 2; i++ {
		if e := f.c.CollectApprovalNotifications(ctx); e != nil {
			t.Fatal(e)
		}
	}
	var n int
	if e := f.db.QueryRow(`SELECT count(*) FROM keygate.approval_notifications WHERE environment=$1 AND request_id=$2 AND kind='approval_due'`, f.c.environment, r.ID).Scan(&n); e != nil || n != 3 {
		t.Fatal("到期提醒缺失或重复", n, e)
	}
	retimeApproval(t, f, r.ID, -time.Second)
	if e := f.c.CollectApprovalNotifications(ctx); e != nil {
		t.Fatal(e)
	}
	if e := f.db.QueryRow(`SELECT count(*) FROM keygate.approval_notifications WHERE environment=$1 AND request_id=$2 AND kind='approval_expired'`, f.c.environment, r.ID).Scan(&n); e != nil || n != 3 {
		t.Fatal("超时通知", n, e)
	}
	current, e := f.c.Request(ctx, f.tokens[0], r.ID)
	if e != nil || !current.Expired {
		t.Fatal("未返回权威超时状态", e)
	}
	if _, e = f.c.WithdrawRequest(ctx, f.tokens[0], r.ID, current.Digest, "超时后不可撤回", unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("超时被改写为撤回", e)
	}
	if _, e = f.c.Vote(ctx, f.tokens[1], r.ID, current.Digest, true, unique(t)); e == nil {
		t.Fatal("过期仍批准")
	}
}
func TestWithdrawAndExecuteRaceHasSingleOutcome(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	r := submitApproved(t, f, ControlOperation{Kind: CreateClient, ClientID: "notice-race", Name: "通知测试", ProfileID: "backend", ProfileVersion: 1})
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	go func() {
		defer wg.Done()
		_, e := f.c.WithdrawRequest(ctx, f.tokens[0], r.ID, r.Digest, "并发撤回测试", unique(t))
		results <- e
	}()
	go func() { defer wg.Done(); results <- f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)) }()
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("撤回执行未形成唯一结果", successes)
	}
	current, e := f.c.Request(ctx, f.tokens[0], r.ID)
	if e != nil || current.Executed == (current.Decision == "cancelled") {
		t.Fatal("终态不一致", e)
	}
}

type approvalSink struct {
	calls   []ApprovalNotification
	failure bool
	during  func()
}

func (p *approvalSink) SendApprovalNotification(_ context.Context, v ApprovalNotification) error {
	p.calls = append(p.calls, v)
	if p.during != nil {
		p.during()
	}
	if p.failure {
		return errors.New("模拟插件不可用")
	}
	return nil
}
func TestNotificationRetryRevocationAndLateResponse(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	r := submitClient(t, f, "notice-retry")
	var id string
	if e := f.db.QueryRow(`SELECT id FROM keygate.approval_notifications WHERE environment=$1 AND request_id=$2 ORDER BY id LIMIT 1`, f.c.environment, r.ID).Scan(&id); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`UPDATE keygate.approval_notifications SET state='obsolete' WHERE environment=$1 AND id<>$2`, f.c.environment, id); e != nil {
		t.Fatal(e)
	}
	sink := &approvalSink{failure: true}
	for i := 0; i < 5; i++ {
		if _, e := f.db.Exec(`UPDATE keygate.approval_notifications SET next_attempt=clock_timestamp()-interval '1 second' WHERE environment=$1 AND id=$2`, f.c.environment, id); e != nil {
			t.Fatal(e)
		}
		if worked, e := f.c.DispatchApprovalNotification(ctx, sink); e != nil || !worked {
			t.Fatal("重试失败", e)
		}
	}
	if len(sink.calls) != 5 {
		t.Fatal("重试次数", len(sink.calls))
	}
	for _, v := range sink.calls {
		if v.ID != id {
			t.Fatal("重试更换幂等键")
		}
	}
	var state string
	if e := f.db.QueryRow(`SELECT state FROM keygate.approval_notifications WHERE environment=$1 AND id=$2`, f.c.environment, id).Scan(&state); e != nil || state != "failed" {
		t.Fatal("重试上限", state, e)
	}
	late := submitClient(t, f, "notice-late")
	sink = &approvalSink{during: func() {
		if _, e := f.c.WithdrawRequest(ctx, f.tokens[0], late.ID, late.Digest, "投递过程中撤回", unique(t)); e != nil {
			t.Fatal(e)
		}
	}}
	if worked, e := f.c.DispatchApprovalNotification(ctx, sink); e != nil || !worked {
		t.Fatal(e)
	}
	if len(sink.calls) != 1 {
		t.Fatal("未调用插件")
	}
	if e := f.db.QueryRow(`SELECT state FROM keygate.approval_notifications WHERE environment=$1 AND id=$2`, f.c.environment, sink.calls[0].ID).Scan(&state); e != nil || state != "obsolete" {
		t.Fatal("迟到响应复活已撤回提醒", state, e)
	}
	revoked := submitClient(t, f, "notice-revoked")
	if _, e := f.db.Exec(`UPDATE keygate.approval_notifications SET state='obsolete' WHERE environment=$1 AND request_id<>$2`, f.c.environment, revoked.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND role='approver'`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	sink = &approvalSink{}
	if worked, e := f.c.DispatchApprovalNotification(ctx, sink); e != nil || !worked || len(sink.calls) != 0 {
		t.Fatal("撤权后仍投递", e)
	}
}
