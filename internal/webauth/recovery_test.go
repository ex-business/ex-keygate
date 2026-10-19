package webauth

import (
	"context"
	"testing"
)

func TestResumeRequiresQuarantinedDomainAndLeavesRootSetEmpty(t *testing.T) {
	a := setupFlow(t, true)
	ctx := context.Background()
	env := a.service.flow.environment
	resumed, e := New(a.service.config, a.store, a.service.protector)
	if e != nil {
		t.Fatal(e)
	}
	if e = resumed.ResumeQuarantinedSimulatedFlow(ctx, env); e == nil {
		t.Fatal("未隔离的域可恢复")
	}
	cp, e := a.store.CaptureSafetyCheckpoint(ctx, env)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.store.QuarantineRestored(ctx, cp, "restore-test"); e != nil {
		t.Fatal(e)
	}
	latest, e := a.store.CaptureSafetyCheckpoint(ctx, env)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.store.VerifySafetyCheckpoint(ctx, latest); e != nil {
		t.Fatal(e)
	}
	if e = resumed.ResumeQuarantinedSimulatedFlow(ctx, env); e != nil {
		t.Fatal(e)
	}
	keys, root := resumed.flow.keySnapshot()
	if len(keys) != 0 || root != "" {
		t.Fatal("恢复加载了旧根")
	}
	// 新登录仍认领原审批人和授权，恢复不重新 bootstrap，也不创建默认管理员。
	owner := a.loginAs(t, "demo-requester")
	if _, e = resumed.flow.control.Clients(ctx, owner.cookie.Value); e != nil {
		t.Fatal("原身份无法重新登录管理", e)
	}
}
