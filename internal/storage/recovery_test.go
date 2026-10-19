package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"ex-keygate/internal/httpsign"
	"fmt"
	"strings"
	"testing"
	"time"
)

func recoveryOp(t *testing.T, f keyFixture, kind, id, incident string, version uint64) ControlOperation {
	t.Helper()
	cl, e := f.f.c.Client(context.Background(), f.f.tokens[0], "one")
	if e != nil {
		t.Fatal(e)
	}
	op := ControlOperation{Kind: kind, ClientID: "one", ExpectedRevision: cl.Revision, KeyVersion: version, RecoveryID: id, IncidentID: incident, EvidenceHash: strings.Repeat("c", 64)}
	if kind == RecoverIssue {
		op.RootID = f.k.rootID
		op.RecipientPublicKey = f.encoded
		op.RecipientFingerprint = f.fingerprint
		op.RecipientSigningKey = f.signingKey
		op.RecipientSigningFingerprint = f.signingFingerprint
		op.NotAfter = time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return op
}
func submitApproved(t *testing.T, f controlFixture, op ControlOperation) ControlRequest {
	t.Helper()
	r, e := f.c.Submit(context.Background(), f.tokens[0], op, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	approveControl(t, f, r)
	return r
}

func TestIsolatedRecoveryAfterRootLeak(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	b, old := f.claim(t, r)
	defer clear(old)
	mac := hmac.New(sha256.New, old)
	mac.Write(b.PossessionInput)
	if e := f.k.ConfirmPossession(ctx, r.ID, mac.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	f.operation(t, ActivateKey, 1, "")
	incident := unique(t)
	if e := f.f.c.Revoke(ctx, f.f.tokens[0], RevocationInput{IncidentID: incident, RootID: f.k.rootID, Reason: "confirmed_leak"}, unique(t)); e != nil {
		t.Fatal(e)
	}
	// 根材料和预算只能由独立批准的新根创建流程产生，不覆盖已泄露根。
	nr := submitApproved(t, f.f, ControlOperation{Kind: ProvisionRoot, ClientID: "root-management", RootID: unique(t)})
	if e := f.f.c.ExecuteLocal(ctx, nr.ID, nr.Digest, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("普通执行器伪造根", e)
	}
	k, e := f.f.c.ProvisionSoftwareRootRequested(ctx, f.f.tokens[0], nr.ID, nr.Digest, unique(t), "login-root")
	if e != nil {
		t.Fatal(e)
	}
	f.k = k
	id := unique(t)
	op := recoveryOp(t, f, RecoverIssue, id, incident, 2)
	r = submitApproved(t, f.f, op)
	if e = f.k.ExecuteIssueRequested(ctx, f.f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	// 普通签发仍拒绝，隔离交付只允许已批准恢复任务固定的新版本。
	normal := op
	normal.Kind = IssueKey
	normal.RecoveryID = ""
	normal.IncidentID = ""
	normal.EvidenceHash = ""
	cl, _ := f.f.c.Client(ctx, f.f.tokens[0], "one")
	normal.ExpectedRevision = cl.Revision
	normal.KeyVersion = 3
	if _, e = f.f.c.Submit(ctx, f.f.tokens[0], normal, unique(t), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("隔离期间普通签发", e)
	}
	bundle, newSecret := f.claim(t, r)
	defer clear(newSecret)
	newMAC := hmac.New(sha256.New, newSecret)
	newMAC.Write(bundle.PossessionInput)
	if e = f.k.ConfirmPossession(ctx, r.ID, newMAC.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	before, beforeMessage := signedProbe(t, f, newSecret, []byte(`{}`))
	beforeMessage.Version = 2
	if e = httpsign.Sign(before, []byte(`{}`), newSecret, beforeMessage); e != nil {
		t.Fatal(e)
	}
	if e = f.k.AuthenticateProbe(ctx, before, []byte(`{}`), "keygate-probe"); e == nil {
		t.Fatal("隔离新凭据提前认证")
	}
	cl, _ = f.f.c.Client(ctx, f.f.tokens[0], "one")
	if cl.State != "disabled" {
		t.Fatal("准备阶段放行")
	}
	op = recoveryOp(t, f, RecoverActivate, id, incident, 2)
	activate := submitApproved(t, f.f, op)
	// 审计写入失败不能部分恢复客户端或密钥。
	constraint := "audit_fault_" + unique(t)
	if _, e = f.f.db.Exec(fmt.Sprintf("ALTER TABLE keygate.audit_events ADD CONSTRAINT %s CHECK(action <> 'control_execute' OR target_id <> '%s')", constraint, activate.ID)); e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.ExecuteRequested(ctx, f.f.tokens[0], activate.ID, activate.Digest, unique(t)); e == nil {
		t.Fatal("审计失败恢复")
	}
	cl, _ = f.f.c.Client(ctx, f.f.tokens[0], "one")
	if cl.State != "disabled" {
		t.Fatal("部分恢复")
	}
	if _, e = f.f.db.Exec("ALTER TABLE keygate.audit_events DROP CONSTRAINT " + constraint); e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.ExecuteRequested(ctx, f.f.tokens[0], activate.ID, activate.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	tasks, e := f.f.c.Recoveries(ctx, f.f.tokens[0], "one")
	if e != nil || len(tasks) != 1 || tasks[0].State != "completed" {
		t.Fatal(tasks, e)
	}
	after, afterMessage := signedProbe(t, f, newSecret, []byte(`{}`))
	afterMessage.Version = 2
	if e = httpsign.Sign(after, []byte(`{}`), newSecret, afterMessage); e != nil {
		t.Fatal(e)
	}
	if e = f.k.AuthenticateProbe(ctx, after, []byte(`{}`), "keygate-probe"); e != nil {
		t.Fatal("恢复新凭据不能认证", e)
	}
	oldKey, e := f.f.c.Key(ctx, f.f.tokens[0], "one", 1)
	if e != nil || oldKey.State != "compromised" {
		t.Fatal(oldKey, e)
	}
	newKey, e := f.f.c.Key(ctx, f.f.tokens[0], "one", 2)
	if e != nil || newKey.State != "active" {
		t.Fatal(newKey, e)
	}
	request, _ := signedProbe(t, f, old, []byte(`{}`))
	if e = f.k.AuthenticateProbe(ctx, request, []byte(`{}`), "keygate-probe"); e == nil {
		t.Fatal("旧材料恢复有效")
	}
	if e = f.f.c.AbortRecovery(ctx, f.f.tokens[0], id, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("已完成恢复可中止", e)
	}
}

func TestRecoveryAbortRevokesOldVotes(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	if e := f.f.c.EmergencyDisableClient(ctx, f.f.tokens[0], "one", unique(t)); e != nil {
		t.Fatal(e)
	}
	id, incident := unique(t), unique(t)
	r := submitApproved(t, f.f, recoveryOp(t, f, RecoverIssue, id, incident, 1))
	if e := f.k.ExecuteIssue(ctx, r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	b, secret := f.claim(t, r)
	defer clear(secret)
	mac := hmac.New(sha256.New, secret)
	mac.Write(b.PossessionInput)
	if e := f.k.ConfirmPossession(ctx, r.ID, mac.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	act := submitApproved(t, f.f, recoveryOp(t, f, RecoverActivate, id, incident, 1))
	// 模拟资格校验后、最终状态更新前跨过有效期，最终 SQL 必须拒绝且事务整体回滚。
	tx, e := f.f.c.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, m, e := f.f.c.loadRequest(ctx, tx, act.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.validateOperation(ctx, tx, m.Operation); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.key_versions SET not_before=clock_timestamp()-interval '1 hour',not_after=clock_timestamp()-interval '1 second' WHERE environment=$1 AND client_id='one' AND version=1`, f.f.c.environment); e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.applyKeyOperation(ctx, tx, m, nil); !errors.Is(e, ErrConflict) {
		t.Fatal("截止边界仍恢复", e)
	}
	tx.Rollback()
	if e := f.f.c.AbortRecovery(ctx, f.f.tokens[0], id, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := f.f.c.ExecuteLocal(ctx, act.ID, act.Digest, unique(t)); e == nil {
		t.Fatal("旧审批在中止后恢复")
	}
	request, _ := signedProbe(t, f, secret, []byte(`{}`))
	if e := f.k.AuthenticateProbe(ctx, request, []byte(`{}`), "keygate-probe"); e == nil {
		t.Fatal("中止凭据认证")
	}
}
