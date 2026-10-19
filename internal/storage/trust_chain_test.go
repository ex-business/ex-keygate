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

func TestApplicationTrustApprovalRotationRevocation(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	root, rootKey, e := trustchain.NewRoot("app-root", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.RegisterApplicationRootOffline(ctx, "app-test", root, unique(t)); e != nil {
		t.Fatal(e)
	}
	counters := []int64{0, 0, 0}
	complete := func(who int, purpose string) { counters[who]++; completeNative(t, f, who, purpose, counters[who]) }
	complete(0, "management")
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, e := trustchain.Issue(root, rootKey, pub, "app-test", trustchain.ServicePurpose, "api-service", 1, now, now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	op := ControlOperation{Kind: PublishTrustCertificate, ClientID: "api-service", KeyVersion: 1, TrustRootFingerprint: trustchain.Fingerprint(root), TrustCertificate: cert, TrustProof: trustchain.PossessionProof(cert, key)}
	request, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], request.ID, request.Digest, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("未经审批发布证书", e)
	}
	approve := func(r ControlRequest) {
		for _, who := range []int{1, 2} {
			complete(who, r.ID)
			if _, e := f.c.Vote(ctx, f.tokens[who], r.ID, r.Digest, true, unique(t)); e != nil {
				t.Fatal(e)
			}
		}
		if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	approve(request)
	_, current, e := f.c.TrustStatusSnapshot(ctx, "api-service", unique(t))
	if e != nil || current.Version != 1 || current.Disabled || current.Revision != 1 {
		t.Fatal("发布状态错误", e, current)
	}
	// 不同节点读取同一权威状态；新证书仍由客户端原先固定的根验证。
	otherStore, _ := New(f.db)
	other, _ := NewDevelopmentControl("test", f.c.environment, f.c.profile, otherStore)
	if e = other.RevokeTrustService(ctx, f.tokens[1], "api-service", 1, "confirmed_leak", unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("无应急权限撤销", e)
	}
	if e = other.RevokeTrustService(ctx, f.tokens[0], "api-service", 1, "confirmed_leak", unique(t)); e != nil {
		t.Fatal(e)
	}
	_, current, e = f.c.TrustStatusSnapshot(ctx, "api-service", unique(t))
	if e != nil || !current.Disabled || current.Revision != 2 {
		t.Fatal("撤销未跨节点可见", e)
	}
	pub, key, _ = ed25519.GenerateKey(rand.Reader)
	cert, e = trustchain.Issue(root, rootKey, pub, "app-test", trustchain.ServicePurpose, "api-service", 2, now, now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	op.KeyVersion = 2
	op.ExpectedRevision = 1
	op.TrustCertificate = cert
	op.TrustProof = trustchain.PossessionProof(cert, key)
	if _, e = f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("旧修订申请被接受", e)
	}
	op.ExpectedRevision = 2
	request, e = f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	approve(request)
	_, current, e = other.TrustStatusSnapshot(ctx, "api-service", unique(t))
	if e != nil || current.Version != 2 || current.Disabled || current.Revision != 3 {
		t.Fatal("轮换状态错误", e)
	}
	var oldState string
	if e = f.db.QueryRow(`SELECT state FROM keygate.application_trust_certificates WHERE environment=$1 AND service_id='api-service' AND version=1`, f.c.environment).Scan(&oldState); e != nil || oldState != "revoked" {
		t.Fatal("旧泄露版本复活", e)
	}
	op = ControlOperation{Kind: DisableTrustService, ClientID: "api-service", ExpectedRevision: 3, KeyVersion: 2, TrustRootFingerprint: trustchain.Fingerprint(root)}
	request, e = f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	approve(request)
	_, current, e = f.c.TrustStatusSnapshot(ctx, "api-service", unique(t))
	if e != nil || !current.Disabled {
		t.Fatal("正常停用失败", e)
	}
}
func TestTrustStatusUsesAuthorityTimeAndCommit(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	root, key, _ := trustchain.NewRoot("app-root", now)
	if e := f.c.RegisterApplicationRootOffline(ctx, "app-test", root, unique(t)); e != nil {
		t.Fatal(e)
	}
	pub, statusKey, _ := ed25519.GenerateKey(rand.Reader)
	statusCert, _ := trustchain.Issue(root, key, pub, "app-test", trustchain.StatusPurpose, "trust-status", 1, now, now.Add(time.Hour))
	pub, _, _ = ed25519.GenerateKey(rand.Reader)
	cert, _ := trustchain.Issue(root, key, pub, "app-test", trustchain.ServicePurpose, "api-service", 1, now, now.Add(time.Hour))
	if _, e := f.db.Exec(`INSERT INTO keygate.application_trust_services(environment,service_id,revision,active_version) VALUES($1,'api-service',1,1)`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`INSERT INTO keygate.application_trust_certificates(environment,service_id,version,fingerprint,certificate,state) VALUES($1,'api-service',1,$2,$3,'active')`, f.c.environment, trustchain.Fingerprint(cert), cert); e != nil {
		t.Fatal(e)
	}
	nonce, _ := trustchain.NewNonce()
	sign := func(r ApplicationRoot, s TrustService, at time.Time) (trustchain.Status, error) {
		return trustchain.SignStatus(root, statusCert, statusKey, trustchain.Status{Environment: r.Environment, ServiceID: s.ServiceID, Revision: s.Revision, Version: s.Version, CertificateHash: s.CertificateHash, Disabled: s.Disabled, Nonce: nonce, Audience: "app"}, at)
	}
	proof, e := f.c.IssueTrustStatus(ctx, "api-service", unique(t), sign)
	if e != nil || len(proof.Signature) == 0 {
		t.Fatal(e)
	}
	if _, e = f.c.IssueTrustStatus(ctx, "api-service", unique(t), func(r ApplicationRoot, s TrustService, at time.Time) (trustchain.Status, error) {
		return sign(r, s, at.Add(time.Minute))
	}); !errors.Is(e, ErrInvalid) {
		t.Fatal("过期快照被重新计时签发", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	proof, e = f.c.IssueTrustStatus(canceled, "api-service", unique(t), func(r ApplicationRoot, s TrustService, at time.Time) (trustchain.Status, error) {
		out, e := sign(r, s, at)
		cancel()
		return out, e
	})
	if e == nil || len(proof.Signature) != 0 {
		t.Fatal("事务未提交仍泄漏状态证明", e)
	}
}
