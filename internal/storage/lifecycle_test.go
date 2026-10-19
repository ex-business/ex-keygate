package storage

import (
	"context"
	"testing"
	"time"
)

func TestRotationTracking(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	f.stage(t, r)
	f.operation(t, ActivateKey, 1, "")
	cl, e := f.f.c.Client(ctx, f.f.tokens[0], "one")
	if e != nil {
		t.Fatal(e)
	}
	op := ControlOperation{Kind: IssueKey, ClientID: "one", ExpectedRevision: cl.Revision, KeyVersion: 2, RotationOf: 1, RootID: f.k.rootID, RecipientPublicKey: f.encoded, RecipientFingerprint: f.fingerprint, RecipientSigningKey: f.signingKey, RecipientSigningFingerprint: f.signingFingerprint, NotAfter: time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")}
	r, e = f.f.c.Submit(ctx, f.f.tokens[0], op, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	approveControl(t, f.f, r)
	if e = f.k.ExecuteIssue(ctx, r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	// 开放轮换期间禁止普通签发绕过冻结来源。
	cl, _ = f.f.c.Client(ctx, f.f.tokens[0], "one")
	bypass := op
	bypass.RotationOf = 0
	bypass.KeyVersion = 3
	bypass.ExpectedRevision = cl.Revision
	if _, e = f.f.c.Submit(ctx, f.f.tokens[0], bypass, unique(t), unique(t)); e != ErrConflict {
		t.Fatal("并行签发绕过轮换", e)
	}
	f.stage(t, r)
	f.operation(t, ActivateKey, 2, time.Now().Add(time.Minute).UTC().Format("2006-01-02T15:04:05.000Z"))
	out, e := f.f.c.Lifecycle(ctx, f.f.tokens[0], "one")
	if e != nil || len(out) != 2 || out[0].RotationState != "overlap" || out[1].RetireAt == nil || !out[1].OriginalNotAfter.After(out[1].NotAfter) {
		t.Fatal(out, e)
	}
	if _, e = f.f.c.store.db.ExecContext(ctx, `UPDATE keygate.key_versions SET not_after=clock_timestamp()-interval '1 second',not_before=clock_timestamp()-interval '1 hour' WHERE environment=$1 AND client_id='one' AND version=1`, f.f.c.environment); e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.MaintainLifecycle(ctx, f.f.tokens[0], unique(t)); e != nil {
		t.Fatal(e)
	}
	out, e = f.f.c.Lifecycle(ctx, f.f.tokens[0], "one")
	if e != nil || out[0].RotationState != "completed" || out[1].State != "expired" {
		t.Fatal(out, e)
	}
	if _, e = f.f.c.store.db.ExecContext(ctx, `UPDATE keygate.key_versions SET not_after=clock_timestamp()-interval '1 second',not_before=clock_timestamp()-interval '1 hour' WHERE environment=$1 AND client_id='one' AND version=2`, f.f.c.environment); e != nil {
		t.Fatal(e)
	}
	out, e = f.f.c.Lifecycle(ctx, f.f.tokens[0], "one")
	if e != nil || out[0].Reminder || out[0].State != "expired" {
		t.Fatal("过期版本错误提醒", out, e)
	}
	if e = f.f.c.MaintainLifecycle(ctx, f.f.tokens[1], unique(t)); e != ErrDenied {
		t.Fatal("非应急人员维护", e)
	}
}
