package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"ex-keygate/trustchain"
	"testing"
	"time"
)

type reminderPluginFunc func(context.Context, TrustReminder) error

func (f reminderPluginFunc) SendTrustReminder(ctx context.Context, v TrustReminder) error {
	return f(ctx, v)
}
func TestTrustRenewalStatusApprovalAndReminders(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	root, rootKey, _ := trustchain.NewRoot("renewal-root", now)
	fp := trustchain.Fingerprint(root)
	if e := f.c.RegisterApplicationRootOffline(ctx, "app-test", root, unique(t)); e != nil {
		t.Fatal(e)
	}
	counters := []int64{0, 0, 0}
	complete := func(who int, purpose string) { counters[who]++; completeNative(t, f, who, purpose, counters[who]) }
	complete(0, "management")
	approve := func(op ControlOperation) ControlRequest {
		t.Helper()
		r, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
		if e != nil {
			t.Fatal(e)
		}
		for _, who := range []int{1, 2} {
			complete(who, r.ID)
			if _, e = f.c.Vote(ctx, f.tokens[who], r.ID, r.Digest, true, unique(t)); e != nil {
				t.Fatal(e)
			}
		}
		return r
	}
	execute := func(r ControlRequest) {
		t.Helper()
		if e := f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	issue := func(purpose, service string, version uint64, hours time.Duration) ([]byte, ed25519.PrivateKey) {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		cert, e := trustchain.Issue(root, rootKey, pub, "app-test", purpose, service, version, now, now.Add(hours))
		if e != nil {
			t.Fatal(e)
		}
		return cert, key
	}
	oldStatus, oldKey := issue(trustchain.StatusPurpose, "trust-status", 1, time.Hour)
	if e := f.c.RegisterTrustStatusOffline(ctx, fp, oldStatus, unique(t)); e != nil {
		t.Fatal(e)
	}
	cert, key := issue(trustchain.ServicePurpose, "orders-api", 1, 30*time.Minute)
	op := ControlOperation{Kind: PublishTrustCertificate, ClientID: "orders-api", KeyVersion: 1, TrustRootFingerprint: fp, TrustCertificate: cert, TrustProof: trustchain.PossessionProof(cert, key)}
	execute(approve(op))
	if e := f.c.CollectTrustReminders(ctx); e != nil {
		t.Fatal(e)
	}
	if e := f.c.CollectTrustReminders(ctx); e != nil {
		t.Fatal(e)
	}
	reminders, e := f.c.TrustReminders(ctx, f.tokens[0])
	if e != nil || len(reminders) != 2 {
		t.Fatal("提醒未按证书去重", len(reminders), e)
	}
	if _, e = f.c.TrustReminders(ctx, f.tokens[1]); !errors.Is(e, ErrDenied) {
		t.Fatal("越权读取提醒", e)
	}
	newCert, newKey := issue(trustchain.ServicePurpose, "orders-api", 2, 2*time.Hour)
	renewal := op
	renewal.Kind = RenewTrustCertificate
	renewal.KeyVersion = 2
	renewal.ExpectedRevision = 1
	renewal.TrustCertificate = newCert
	renewal.TrustProof = trustchain.PossessionProof(newCert, newKey)
	invalid := renewal
	invalid.TrustCertificate, invalid.TrustProof = cert, trustchain.PossessionProof(cert, key)
	if _, e = f.c.Submit(ctx, f.tokens[0], invalid, unique(t), unique(t)); e == nil {
		t.Fatal("错误版本续期被接受")
	}
	shortCert, shortKey := issue(trustchain.ServicePurpose, "orders-api", 2, 20*time.Minute)
	invalid.TrustCertificate = shortCert
	invalid.TrustProof = trustchain.PossessionProof(shortCert, shortKey)
	if _, e = f.c.Submit(ctx, f.tokens[0], invalid, unique(t), unique(t)); e == nil {
		t.Fatal("未延长有效期的续期被接受")
	}
	r := approve(renewal)
	execute(r)
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal("续期执行重试不幂等", e)
	}
	detail, _, e := f.c.TrustCertificateDetail(ctx, f.tokens[0], "orders-api", 2, false, unique(t))
	if e != nil || detail.Changes[0].Reason != "approved_renewal" {
		t.Fatal("续期未记录事实", e)
	}
	if e = f.c.CollectTrustReminders(ctx); e != nil {
		t.Fatal(e)
	}
	reminders, e = f.c.TrustReminders(ctx, f.tokens[0])
	if e != nil || len(reminders) != 3 {
		t.Fatal(e, len(reminders))
	}
	for _, v := range reminders {
		if v.Fingerprint == trustchain.Fingerprint(cert) && v.State != "superseded" {
			t.Fatal("旧证书提醒未取消")
		}
	}
	nextStatus, nextKey := issue(trustchain.StatusPurpose, "trust-status", 1, 3*time.Hour)
	statusOp := ControlOperation{Kind: UpdateTrustStatusCertificate, ClientID: "trust-status", ExpectedRevision: 1, KeyVersion: 1, TrustRootFingerprint: fp, TrustCertificate: nextStatus, TrustProof: trustchain.PossessionProof(nextStatus, nextKey)}
	reused, e := trustchain.Issue(root, rootKey, oldKey.Public().(ed25519.PublicKey), "app-test", trustchain.StatusPurpose, "trust-status", 1, now, now.Add(3*time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	badStatus := statusOp
	badStatus.TrustCertificate = reused
	badStatus.TrustProof = trustchain.PossessionProof(reused, oldKey)
	if _, e = f.c.Submit(ctx, f.tokens[0], badStatus, unique(t), unique(t)); e == nil {
		t.Fatal("状态签名器重用旧密钥")
	}
	request, e := f.c.Submit(ctx, f.tokens[0], statusOp, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], request.ID, request.Digest, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("状态证书更新绕过审批", e)
	}
	// 缩小审批人授权不能给共享签名器投票。
	complete(1, request.ID)
	if _, e = f.db.Exec(`UPDATE keygate.role_grants SET client_id='trust-status' WHERE environment=$1 AND principal_id=$2 AND role='approver'`, f.c.environment, f.bootstrap.Principals[1].ID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.Vote(ctx, f.tokens[1], request.ID, request.Digest, true, unique(t)); e == nil {
		t.Fatal("范围审批人批准共享状态签名器")
	}
	if _, e = f.db.Exec(`UPDATE keygate.role_grants SET client_id='' WHERE environment=$1 AND principal_id=$2 AND role='approver'`, f.c.environment, f.bootstrap.Principals[1].ID); e != nil {
		t.Fatal(e)
	}
	execute(approve(statusOp))
	if e = f.c.RegisterTrustStatusOffline(ctx, fp, oldStatus, unique(t)); e != nil {
		t.Fatal(e)
	}
	signers, e := f.c.TrustStatusSigners(ctx, f.tokens[0])
	if e != nil || len(signers) != 1 || signers[0].Revision != 2 || signers[0].Info.Fingerprint != trustchain.Fingerprint(nextStatus) {
		t.Fatal("重启覆盖批准指针", e)
	}
	sign := func(cert []byte, key ed25519.PrivateKey) func(ApplicationRoot, TrustService, time.Time) (trustchain.Status, error) {
		return func(root ApplicationRoot, s TrustService, at time.Time) (trustchain.Status, error) {
			nonce, _ := trustchain.NewNonce()
			return trustchain.SignStatus(root.Certificate, cert, key, trustchain.Status{Environment: root.Environment, ServiceID: s.ServiceID, Revision: s.Revision, Version: s.Version, CertificateHash: s.CertificateHash, Nonce: nonce, Audience: "app"}, at)
		}
	}
	if _, e = f.c.IssueTrustStatus(ctx, "orders-api", unique(t), sign(oldStatus, oldKey)); !errors.Is(e, ErrConflict) {
		t.Fatal("旧节点仍能签发状态", e)
	}
	if _, e = f.c.IssueTrustStatus(ctx, "orders-api", unique(t), sign(nextStatus, nextKey)); e != nil {
		t.Fatal("新节点无法签发", e)
	}
	if e = f.c.CollectTrustReminders(ctx); e != nil {
		t.Fatal(e)
	}
	// 首次超时保持pending，同一ID重试；插件不得将未知结果当成另一次独立发送。
	var attempted TrustReminder
	_, e = f.c.DispatchTrustReminder(ctx, reminderPluginFunc(func(_ context.Context, v TrustReminder) error { attempted = v; return errors.New("timeout") }))
	if e != nil || attempted.ID == "" {
		t.Fatal(e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.application_trust_reminders SET next_attempt=clock_timestamp()-interval '1 second' WHERE id=$1`, attempted.ID); e != nil {
		t.Fatal(e)
	}
	_, e = f.c.DispatchTrustReminder(ctx, reminderPluginFunc(func(_ context.Context, v TrustReminder) error {
		if v.ID != attempted.ID || v.Attempts != 2 {
			t.Error("重试没有复用幂等键", v.ID, v.Attempts)
		}
		return nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	var state string
	if e = f.db.QueryRow(`SELECT state FROM keygate.application_trust_reminders WHERE id=$1`, attempted.ID).Scan(&state); e != nil || state != "sent" {
		t.Fatal(state, e)
	}
	// 旧材料的应急撤销后，续期不能作为重新上线入口。
	if e = f.c.RevokeTrustService(ctx, f.tokens[0], "orders-api", 2, "confirmed_leak", unique(t)); e != nil {
		t.Fatal(e)
	}
	fresh, freshKey := issue(trustchain.ServicePurpose, "orders-api", 3, 4*time.Hour)
	renewal.KeyVersion = 3
	renewal.ExpectedRevision = 3
	renewal.TrustCertificate = fresh
	renewal.TrustProof = trustchain.PossessionProof(fresh, freshKey)
	if _, e = f.c.Submit(ctx, f.tokens[0], renewal, unique(t), unique(t)); e == nil {
		t.Fatal("续期绕过撤销恢复")
	}
	if e = f.c.CollectTrustReminders(ctx); e != nil {
		t.Fatal(e)
	}
	// 模拟发送超时后的迟到完成：期间取消的提醒不可被回写为sent。
	if _, e = f.db.Exec(`UPDATE keygate.application_trust_reminders SET state='pending',next_attempt=clock_timestamp()-interval '1 second' WHERE environment=$1 AND kind='status' AND fingerprint=$2`, f.c.environment, trustchain.Fingerprint(nextStatus)); e != nil {
		t.Fatal(e)
	}
	_, e = f.c.DispatchTrustReminder(ctx, reminderPluginFunc(func(_ context.Context, v TrustReminder) error {
		_, err := f.db.Exec(`UPDATE keygate.application_trust_reminders SET state='superseded' WHERE id=$1`, v.ID)
		return err
	}))
	if e != nil {
		t.Fatal(e)
	}
	var sentCount int
	if e = f.db.QueryRow(`SELECT count(*) FROM keygate.application_trust_reminders WHERE environment=$1 AND kind='status' AND fingerprint=$2 AND state='sent'`, f.c.environment, trustchain.Fingerprint(nextStatus)).Scan(&sentCount); e != nil || sentCount != 0 {
		t.Fatal("迟到响应覆盖取消", e)
	}

}
func TestReminderSeverityBoundaries(t *testing.T) {
	now := time.Now()
	for _, v := range []struct {
		d    time.Duration
		want string
	}{{8 * 24 * time.Hour, ""}, {7 * 24 * time.Hour, "due_7d"}, {24 * time.Hour, "due_24h"}, {time.Hour, "due_1h"}, {0, "expired"}, {-time.Second, "expired"}} {
		if got := reminderSeverity(now.Add(v.d), now); got != v.want {
			t.Fatal(v.d, got)
		}
	}
}
