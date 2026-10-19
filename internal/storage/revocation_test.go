package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestRevocationTerminalAndScope(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	f.stage(t, r)
	f.operation(t, ActivateKey, 1, "")
	r = f.issue(t, 2)
	f.stage(t, r)
	in := RevocationInput{IncidentID: unique(t), ClientID: "one", KeyVersion: 1, Reason: "suspected_leak"}
	if e := f.f.c.Revoke(ctx, f.f.tokens[1], in, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("审批人越权撤销", e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- f.f.c.Revoke(ctx, f.f.tokens[0], in, unique(t)) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	k, e := f.f.c.Key(ctx, f.f.tokens[0], "one", 1)
	if e != nil || k.State != "compromised" {
		t.Fatal(k, e)
	}
	k, e = f.f.c.Key(ctx, f.f.tokens[0], "one", 2)
	if e != nil || k.State != "staged" {
		t.Fatal("误伤无关版本", k, e)
	}
	if _, e = f.f.db.ExecContext(ctx, `UPDATE keygate.key_versions SET state='active' WHERE environment=$1 AND client_id='one' AND version=1`, f.f.c.environment); e == nil {
		t.Fatal("撤销被复活")
	}
	in.KeyVersion = 2
	if e = f.f.c.Revoke(ctx, f.f.tokens[0], in, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("事件参数被替换", e)
	}
	in = RevocationInput{IncidentID: unique(t), RootID: f.k.rootID, Reason: "confirmed_leak"}
	if e = f.f.c.Revoke(ctx, f.f.tokens[0], in, unique(t)); e != nil {
		t.Fatal(e)
	}
	cl, e := f.f.c.Client(ctx, f.f.tokens[0], "one")
	if e != nil || cl.State != "disabled" {
		t.Fatal("根撤销未隔离客户端", cl, e)
	}
	k, e = f.f.c.Key(ctx, f.f.tokens[0], "one", 2)
	if e != nil || k.State != "compromised" {
		t.Fatal(k, e)
	}
	if _, e = f.f.c.DeliveryChallenge(ctx, r.ID); !errors.Is(e, ErrDenied) {
		t.Fatal("已撤销根仍交付", e)
	}
}

func TestRevocationAuditRollback(t *testing.T) {
	f := newKeyFixture(t)
	r := f.issue(t, 1)
	_ = r
	ctx := context.Background()
	constraint := "audit_fault_" + unique(t)
	if _, e := f.f.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE keygate.audit_events ADD CONSTRAINT %s CHECK(action <> 'key_revoke' OR target_id <> '%s')", constraint, f.k.rootID)); e != nil {
		t.Fatal(e)
	}
	defer f.f.db.Exec("ALTER TABLE keygate.audit_events DROP CONSTRAINT IF EXISTS " + constraint)
	if e := f.f.c.Revoke(ctx, f.f.tokens[0], RevocationInput{IncidentID: unique(t), RootID: f.k.rootID, Reason: "confirmed_leak"}, unique(t)); e == nil {
		t.Fatal("审计失败仍撤销")
	}

	k, e := f.f.c.Key(ctx, f.f.tokens[0], "one", 1)
	if e != nil || k.State != "pending" {
		t.Fatal(k, e)
	}
}
