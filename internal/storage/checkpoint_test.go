package storage

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestSafetyCheckpointDetectsRevocationBudgetAndNonceRollback(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	_ = f.issue(t, 1)
	checkpoint, e := f.f.c.store.CaptureSafetyCheckpoint(ctx, f.f.c.environment)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.store.VerifySafetyCheckpoint(ctx, checkpoint); e != nil {
		t.Fatal(e)
	}
	incident := unique(t)
	if e = f.f.c.Revoke(ctx, f.f.tokens[0], RevocationInput{IncidentID: incident, ClientID: "one", KeyVersion: 1, Reason: "confirmed_leak"}, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.store.VerifySafetyCheckpoint(ctx, checkpoint); !errors.Is(e, ErrConflict) {
		t.Fatal("旧状态校验点接受新增撤销", e)
	}
	trusted, e := f.f.c.store.CaptureSafetyCheckpoint(ctx, f.f.c.environment)
	if e != nil {
		t.Fatal(e)
	}
	// 在事务内模拟备份丢失最新撤销事实；即使密钥状态仍被触发器保护，外部摘要也必须报不一致。
	tx, e := f.f.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.revocations WHERE environment=$1 AND incident_id=$2`, f.f.c.environment, incident); e != nil {
		t.Fatal(e)
	}
	actual, e := captureSafety(ctx, tx, f.f.c.environment)
	if e != nil {
		t.Fatal(e)
	}
	if matchingSafety(actual, trusted) {
		t.Fatal("撤销丢失未检测")
	}
	tx.Rollback()
	if _, e = f.f.db.ExecContext(ctx, `UPDATE keygate.root_budgets SET used=used-1 WHERE root_id=$1`, f.k.rootID); e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.store.VerifySafetyCheckpoint(ctx, trusted); !errors.Is(e, ErrConflict) {
		t.Fatal("预算回退未检测", e)
	}
	trusted, e = f.f.c.store.CaptureSafetyCheckpoint(ctx, f.f.c.environment)
	if e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	if ok, e := f.f.c.store.ConsumeNonce(ctx, Scope{f.f.c.environment, "one", "one", 1}, nonce, time.Now().Add(time.Minute)); e != nil || !ok {
		t.Fatal(e)
	}
	if e = f.f.c.store.VerifySafetyCheckpoint(ctx, trusted); !errors.Is(e, ErrConflict) {
		t.Fatal("nonce边界丢失未检测", e)
	}
}
func TestQuarantineRestoredInvalidatesSessionsAndPendingApprovals(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	f.stage(t, r)
	activation := submitApproved(t, f.f, ControlOperation{Kind: ActivateKey, ClientID: "one", ExpectedRevision: func() uint64 {
		c, e := f.f.c.Client(ctx, f.f.tokens[0], "one")
		if e != nil {
			t.Fatal(e)
		}
		return c.Revision
	}(), KeyVersion: 1})
	cp, e := f.f.c.store.CaptureSafetyCheckpoint(ctx, f.f.c.environment)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.store.QuarantineRestored(ctx, cp, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.ExecuteLocal(ctx, activation.ID, activation.Digest, unique(t)); e == nil {
		t.Fatal("备份中的旧票仍执行")
	}
	if _, e = f.f.c.Client(ctx, f.f.tokens[0], "one"); !errors.Is(e, ErrDenied) {
		t.Fatal("恢复旧会话仍有效", e)
	}
	if e = f.f.c.CheckQuarantinedOffline(ctx); e != nil {
		t.Fatal(e)
	}
	var state string
	if e = f.f.db.QueryRowContext(ctx, `SELECT state FROM keygate.clients WHERE environment=$1 AND client_id='one'`, f.f.c.environment).Scan(&state); e != nil || state != "disabled" {
		t.Fatal(state, e)
	}
	if e = f.f.c.store.VerifySafetyCheckpoint(ctx, cp); !errors.Is(e, ErrConflict) {
		t.Fatal("隔离后旧校验点仍接受", e)
	}
	after, e := f.f.c.store.CaptureSafetyCheckpoint(ctx, f.f.c.environment)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.store.VerifySafetyCheckpoint(ctx, after); e != nil {
		t.Fatal(e)
	}
}
