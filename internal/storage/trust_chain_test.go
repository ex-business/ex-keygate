package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"ex-keygate/trustchain"
	"fmt"
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
	detail, download, e := f.c.TrustCertificateDetail(ctx, f.tokens[0], "api-service", 1, true, unique(t))
	if e != nil || !detail.ChainValid || !detail.AuthenticationEligible || trustchain.Fingerprint(download) != trustchain.Fingerprint(cert) {
		t.Fatal("公开证书详情或下载错误", e)
	}
	detail, _, e = f.c.TrustCertificateDetail(ctx, f.tokens[0], "api-service", 1, false, unique(t))
	if e != nil || len(detail.Changes) != 1 || len(detail.Approvals) != 1 || !detail.Approvals[0].Executed {
		t.Fatal("发布变更与申请缺失", e)
	}
	if _, _, e = f.c.TrustCertificateDetail(ctx, f.tokens[1], "api-service", 1, true, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("无查看权限下载", e)
	}
	// 事实表不可写时撤销必须整体回滚，不能出现状态已变而变更记录丢失。
	blocked, e := f.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = blocked.ExecContext(ctx, `LOCK TABLE keygate.application_trust_changes IN ACCESS EXCLUSIVE MODE`); e != nil {
		t.Fatal(e)
	}
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	e = f.c.RevokeTrustService(short, f.tokens[0], "api-service", 1, "confirmed_leak", unique(t))
	cancel()
	blocked.Rollback()
	if e == nil {
		t.Fatal("变更记录故障仍撤销成功")
	}
	detail, _, e = f.c.TrustCertificateDetail(ctx, f.tokens[0], "api-service", 1, false, unique(t))
	if e != nil || !detail.AuthenticationEligible || len(detail.Changes) != 1 {
		t.Fatal("事实写入故障未回滚", e)
	}
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
	if e = other.RevokeTrustService(ctx, f.tokens[0], "api-service", 1, "suspected_leak", unique(t)); e != nil {
		t.Fatal(e)
	}
	detail, _, e = f.c.TrustCertificateDetail(ctx, f.tokens[0], "api-service", 1, false, unique(t))
	if e != nil || detail.AuthenticationEligible || len(detail.Changes) != 2 || detail.Changes[0].Reason != "confirmed_leak" {
		t.Fatal("撤销事实不正确或重复", e)
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
	history, e := f.c.TrustCertificateHistory(ctx, f.tokens[0], "api-service", 0, 1)
	if e != nil || len(history.Certificates) != 1 || history.Certificates[0].Version != 2 || !history.HasMore {
		t.Fatal("历史分页首屏", e)
	}
	history, e = f.c.TrustCertificateHistory(ctx, f.tokens[0], "api-service", history.NextBefore, 1)
	if e != nil || len(history.Certificates) != 1 || history.Certificates[0].Version != 1 || history.Certificates[0].State != "revoked" || history.HasMore {
		t.Fatal("历史分页次屏", e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.role_grants SET client_id='api-service' WHERE environment=$1 AND principal_id=$2 AND role='viewer' AND client_id=''`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.c.TrustRootDetail(ctx, f.tokens[0], trustchain.Fingerprint(root), true, unique(t)); e != nil {
		t.Fatal("范围查看者无法下载所属根", e)
	}
	otherRoot, _, _ := trustchain.NewRoot("unrelated-root", now)
	if e = f.c.RegisterApplicationRootOffline(ctx, "another-app", otherRoot, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.c.TrustRootDetail(ctx, f.tokens[0], trustchain.Fingerprint(otherRoot), false, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("范围查看者读取其他根", e)
	}
	if _, e = f.c.TrustCertificateHistory(ctx, f.tokens[0], "unrelated-service", 0, 20); !errors.Is(e, ErrDenied) {
		t.Fatal("范围查看者越权读取历史", e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.role_grants SET enabled=false WHERE environment=$1 AND principal_id=$2 AND role='viewer'`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.c.TrustCertificateDetail(ctx, f.tokens[0], "api-service", 1, true, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("撤权后仍可下载", e)
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
	if _, e := f.db.Exec(`INSERT INTO keygate.application_trust_services(environment,service_id,revision,active_version,root_fingerprint) VALUES($1,'api-service',1,1,$2)`, f.c.environment, trustchain.Fingerprint(root)); e != nil {
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

// 多根共享一个管理域，但业务标识、审批内容和状态证明不能跨根混用。
func TestMultipleApplicationRootsIsolation(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	roots := make([][]byte, 3)
	keys := make([]ed25519.PrivateKey, 3)
	for i := range roots {
		roots[i], keys[i], _ = trustchain.NewRoot(fmt.Sprintf("root-%d", i), now)
		if e := f.c.RegisterApplicationRootOffline(ctx, "app-test", roots[i], unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	counters := []int64{0, 0, 0}
	complete := func(who int, purpose string) { counters[who]++; completeNative(t, f, who, purpose, counters[who]) }
	complete(0, "management")
	publish := func(i int, id string) {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		cert, e := trustchain.Issue(roots[i], keys[i], pub, "app-test", trustchain.ServicePurpose, id, 1, now, now.Add(time.Hour))
		if e != nil {
			t.Fatal(e)
		}
		op := ControlOperation{Kind: PublishTrustCertificate, ClientID: id, KeyVersion: 1, TrustRootFingerprint: trustchain.Fingerprint(roots[i]), TrustCertificate: cert, TrustProof: trustchain.PossessionProof(cert, key)}
		// 正确证书配错根时即使附带私钥持有证明也不能提交。
		wrong := op
		wrong.TrustRootFingerprint = trustchain.Fingerprint(roots[(i+1)%3])
		if _, e = f.c.Submit(ctx, f.tokens[0], wrong, unique(t), unique(t)); e == nil {
			t.Fatal("跨根证书被接受")
		}
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
		if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
			t.Fatal(e)
		}
		root, service, e := f.c.TrustStatusSnapshot(ctx, id, unique(t))
		if e != nil || root.Fingerprint != op.TrustRootFingerprint || service.RootFingerprint != root.Fingerprint {
			t.Fatal("状态读取选错根", e)
		}
		pub, statusKey, _ := ed25519.GenerateKey(rand.Reader)
		statusCert, _ := trustchain.Issue(roots[i], keys[i], pub, "app-test", trustchain.StatusPurpose, "trust-status", 1, now, now.Add(time.Hour))
		nonce, _ := trustchain.NewNonce()
		proof, e := f.c.IssueTrustStatus(ctx, id, unique(t), func(root ApplicationRoot, s TrustService, at time.Time) (trustchain.Status, error) {
			return trustchain.SignStatus(root.Certificate, statusCert, statusKey, trustchain.Status{Environment: root.Environment, ServiceID: id, Revision: s.Revision, Version: s.Version, CertificateHash: s.CertificateHash, Nonce: nonce, Audience: "app"}, at)
		})
		if e != nil {
			t.Fatal(e)
		}
		message, _ := trustchain.SignMessage(roots[i], cert, key, "app-test", id, 1, "app", nonce, []byte("test"), time.Now())
		v := trustchain.Verifier{Root: roots[i], Environment: "app-test", ServiceID: id, Audience: "app", State: &trustchain.MemoryState{}}
		if e = v.Verify(message, proof, nonce, []byte("test"), time.Now()); e != nil {
			t.Fatal(e)
		}
		v.Root = roots[(i+1)%3]
		v.State = &trustchain.MemoryState{}
		if v.Verify(message, proof, nonce, []byte("test"), time.Now()) == nil {
			t.Fatal("其他根的客户端接受签名")
		}
		otherIndex := (i + 1) % 3
		otherPub, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
		otherCert, _ := trustchain.Issue(roots[otherIndex], keys[otherIndex], otherPub, "app-test", trustchain.ServicePurpose, id, 2, now, now.Add(time.Hour))
		switchRoot := ControlOperation{Kind: PublishTrustCertificate, ClientID: id, KeyVersion: 2, ExpectedRevision: 1, TrustRootFingerprint: trustchain.Fingerprint(roots[otherIndex]), TrustCertificate: otherCert, TrustProof: trustchain.PossessionProof(otherCert, otherPrivate)}
		if _, e = f.c.Submit(ctx, f.tokens[0], switchRoot, unique(t), unique(t)); !errors.Is(e, ErrConflict) {
			t.Fatal("审批轮换允许更换根", e)
		}
		// 禁止经轮换或直接更新悄悄改变已登记服务的根。
		if _, e = f.db.Exec(`UPDATE keygate.application_trust_services SET root_fingerprint=$1 WHERE environment=$2 AND service_id=$3`, trustchain.Fingerprint(roots[(i+1)%3]), f.c.environment, id); e == nil {
			t.Fatal("数据库允许换根")
		}
	}
	for i, id := range []string{"orders-api", "billing-api", "partner-api"} {
		publish(i, id)
	}
	catalog, services, e := f.c.TrustServices(ctx, f.tokens[0])
	if e != nil || len(catalog) != 3 || len(services) != 3 {
		t.Fatal("多根目录错误", e, len(catalog), len(services))
	}
	if e = f.c.RevokeTrustService(ctx, f.tokens[0], "orders-api", 1, "confirmed_leak", unique(t)); e != nil {
		t.Fatal(e)
	}
	_, other, e := f.c.TrustStatusSnapshot(ctx, "billing-api", unique(t))
	if e != nil || other.Disabled || other.Revision != 1 {
		t.Fatal("撤销波及其他根", e)
	}
	if _, e = f.db.Exec(`INSERT INTO keygate.application_trust_services(environment,service_id,revision,active_version) VALUES($1,'ambiguous-service',1,0)`, f.c.environment); e == nil {
		t.Fatal("多根域隐式绑定根")
	}
}

func TestExpiredHistoricalCertificateRemainsReadable(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-2 * time.Hour)
	root, key, _ := trustchain.NewRoot("historical-root", past)
	if e := f.c.RegisterApplicationRootOffline(ctx, "app-test", root, unique(t)); e != nil {
		t.Fatal(e)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cert, e := trustchain.Issue(root, key, pub, "app-test", trustchain.ServicePurpose, "expired-api", 1, past, past.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Exec(`INSERT INTO keygate.application_trust_services(environment,service_id,revision,active_version,root_fingerprint) VALUES($1,'expired-api',1,1,$2)`, f.c.environment, trustchain.Fingerprint(root)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Exec(`INSERT INTO keygate.application_trust_certificates(environment,service_id,version,fingerprint,certificate,state) VALUES($1,'expired-api',1,$2,$3,'active')`, f.c.environment, trustchain.Fingerprint(cert), cert); e != nil {
		t.Fatal(e)
	}
	completeNative(t, f, 0, "management", 1)
	detail, der, e := f.c.TrustCertificateDetail(ctx, f.tokens[0], "expired-api", 1, true, unique(t))
	if e != nil || !detail.ChainValid || detail.AuthenticationEligible || detail.Certificate.Info.Validity != "expired" || trustchain.Fingerprint(der) != trustchain.Fingerprint(cert) {
		t.Fatal("过期历史被当作无效链或可认证", e)
	}
	detail, _, e = f.c.TrustCertificateDetail(ctx, f.tokens[0], "expired-api", 1, false, unique(t))
	if e != nil || len(detail.Changes) != 0 || len(detail.Approvals) != 0 {
		t.Fatal("旧证书补造事件", e)
	}
}
