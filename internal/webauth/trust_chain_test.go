package webauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/storage"
	"ex-keygate/trustchain"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestApplicationTrustHTTPFlow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, rootKey, _ := trustchain.NewRoot("app-root", now)
	pub, statusKey, _ := ed25519.GenerateKey(rand.Reader)
	statusCert, _ := trustchain.Issue(root, rootKey, pub, "app-test", trustchain.StatusPurpose, "trust-status", 1, now, now.Add(time.Hour))
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, _ := trustchain.Issue(root, rootKey, pub, "app-test", trustchain.ServicePurpose, "app-server", 1, now, now.Add(time.Hour))
	delivery := &testDelivery{sent: map[string]mfa.Delivery{}}
	plan := MFAEnrollmentPlan{WitnessSubjects: [2]string{"demo-requester", "demo-approver-1"}, EvidenceHash: strings.Repeat("c", 64), ApproverSubjects: []string{"demo-approver-1", "demo-approver-2"}, M: 2}
	for i, subject := range []string{"demo-requester", "demo-approver-1", "demo-approver-2"} {
		plan.People = append(plan.People, MFAEnrollmentPerson{Subject: subject, Policy: mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.Email, M: 1, N: 1, Required: true}}}, Factors: []MFAEnrollmentFactor{{ID: "mail", Method: mfa.Email, Label: "本人邮件", Reference: fmt.Sprintf("test%d@example.invalid", i)}}})
	}
	a := setupFlowInitialized(t, true, "", func(c *Config) { c.MFAPlugins.Email = delivery; c.MFAPluginPolicyHash = strings.Repeat("a", 64) }, func(s *Service) {
		if e := s.ProvisionNativeMFAOffline(context.Background(), plan); e != nil {
			t.Fatal(e)
		}
		if e := s.ConfigureApplicationTrust(context.Background(), "app-test", root, statusCert, statusKey); e != nil {
			t.Fatal(e)
		}
		otherRoot, otherKey, _ := trustchain.NewRoot("second-root", now)
		otherPublic, otherStatusKey, _ := ed25519.GenerateKey(rand.Reader)
		otherStatusCert, _ := trustchain.Issue(otherRoot, otherKey, otherPublic, "partner-test", trustchain.StatusPurpose, "trust-status", 1, now, now.Add(time.Hour))
		if e := s.ConfigureApplicationTrust(context.Background(), "partner-test", otherRoot, otherStatusCert, otherStatusKey); e != nil {
			t.Fatal(e)
		}
		if e := s.ConfigureApplicationTrust(context.Background(), "partner-test", otherRoot, otherStatusCert, otherStatusKey); e == nil {
			t.Fatal("重复装配同一根")
		}

	})
	// 原生验证模式登录后尚未取得管理权限，不能复用假定管理已授权的旧测试助手。
	actors := make([]businessActor, 0, 3)
	for _, subject := range []string{"demo-requester", "demo-approver-1", "demo-approver-2"} {
		cookie := nativeLogin(t, a, subject)
		actors = append(actors, businessActor{cookie: cookie, csrf: csrf(cookie.Value)})
	}
	complete := func(who int, purpose string) {
		t.Helper()
		status, raw := nativeHTTP(t, a, actors[who].cookie, "POST", "/api/mfa/challenges", map[string]string{"purpose": purpose})
		if status != 200 {
			t.Fatal("验证启动失败", status)
		}
		var result struct {
			State storage.MFAState `json:"state"`
		}
		json.Unmarshal(raw, &result)
		path := "/api/mfa/challenges/" + result.State.ID + "/factors/mail"
		status, raw = nativeHTTP(t, a, actors[who].cookie, "POST", path, struct{}{})
		if status != 201 {
			t.Fatal("准备验证失败", status)
		}
		var attempt struct {
			ID string `json:"attemptId"`
		}
		json.Unmarshal(raw, &attempt)
		status, _ = nativeHTTP(t, a, actors[who].cookie, "POST", path+"/verify", map[string]string{"code": delivery.code(attempt.ID)})
		if status != 200 {
			t.Fatal("验证失败", status)
		}
	}
	status, _ := nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services", nil)
	if status != 403 {
		t.Fatal("MFA前读取组织证书", status)
	}
	complete(0, "management")
	for _, path := range []string{"/api/trust/status-signers", "/api/trust/reminders"} {
		status, _ := nativeHTTP(t, a, actors[0].cookie, "GET", path, nil)
		if status != 200 {
			t.Fatal("运维目录读取失败", path, status)
		}
		status, _ = nativeHTTP(t, a, actors[0].cookie, "GET", path+"?limit=20", nil)
		if status != 400 {
			t.Fatal("目录接受任意查询", path, status)
		}
	}

	status, rawCatalog := nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services", nil)
	var catalog struct {
		Roots []storage.ApplicationRoot `json:"roots"`
	}
	if status != 200 || json.Unmarshal(rawCatalog, &catalog) != nil || len(catalog.Roots) != 2 {
		t.Fatal("多根目录接口错误", status)
	}

	op := storage.ControlOperation{Kind: storage.PublishTrustCertificate, ClientID: "app-server", KeyVersion: 1, TrustRootFingerprint: trustchain.Fingerprint(root), TrustCertificate: cert, TrustProof: trustchain.PossessionProof(cert, key)}
	r := a.submitOperation(t, actors[0], op)
	for _, who := range []int{1, 2} {
		complete(who, r.ID)
		status, _ = a.business(t, actors[who], "POST", "/api/requests/"+r.ID+"/votes", map[string]any{"digest": r.Digest, "accept": true})
		if status != 200 {
			t.Fatal("证书审批失败", status)
		}
	}
	a.executeHTTP(t, actors[0], r)
	status, _ = nativeHTTP(t, a, actors[0].cookie, "GET", "/api/config?limit=20", nil)
	if status != 400 {
		t.Fatal("旧业务查询限制被放宽", status)
	}
	status, _ = nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services/app-server/certificates?limit=1&limit=2", nil)
	if status != 400 {
		t.Fatal("重复分页参数", status)
	}
	status, _ = nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services/app-server/certificates?limit=%zz", nil)
	if status != 400 {
		t.Fatal("非法查询编码", status)
	}
	status, rawDownload := nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services/app-server/certificates/1/download?format=pem", nil)
	block, _ := pem.Decode(rawDownload)
	if status != 200 || block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, cert) {
		t.Fatal("公开PEM下载错误", status)
	}
	status, rawDownload = nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services/app-server/certificates/1/download?format=der", nil)
	if _, e := x509.ParseCertificate(rawDownload); status != 200 || e != nil || !bytes.Equal(rawDownload, cert) {
		t.Fatal("公开DER下载错误", status, e)
	}
	status, rawDetail := nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services/app-server/certificates/1", nil)
	var detail storage.TrustCertificateDetail
	if status != 200 || json.Unmarshal(rawDetail, &detail) != nil || !detail.ChainValid || !detail.AuthenticationEligible || len(detail.Changes) != 1 || len(detail.Approvals) != 1 {
		t.Fatal("详情或关联记录错误", status)
	}
	status, _ = nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services/app-server/certificates/01", nil)
	if status != 400 {
		t.Fatal("非规范版本未拒绝", status)
	}
	status, _ = nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/services/app-server/certificates/1/download?format=private", nil)
	if status != 400 {
		t.Fatal("非法下载格式", status)
	}
	status, _ = nativeHTTP(t, a, actors[1].cookie, "GET", "/api/trust/services/app-server/certificates/1/download", nil)
	if status != 403 {
		t.Fatal("无权下载", status)
	}
	status, rawRoot := nativeHTTP(t, a, actors[0].cookie, "GET", "/api/trust/roots/"+trustchain.Fingerprint(root)+"/download?format=der", nil)
	if status != 200 || !bytes.Equal(rawRoot, root) {
		t.Fatal("根下载错误", status)
	}

	nonce, _ := trustchain.NewNonce()
	requestBody := map[string]string{"nonce": nonce, "audience": "my-app"}
	status, raw := nativeHTTP(t, a, actors[0].cookie, "POST", "/api/trust/app-server/status", requestBody)
	if status != 200 {
		t.Fatal("签发状态失败", status)
	}
	var proof trustchain.Status
	if trustchain.DecodeJSON(raw, &proof) != nil {
		t.Fatal("状态结构错误")
	}
	message, e := trustchain.SignMessage(root, cert, key, "app-test", "app-server", 1, "my-app", nonce, []byte("payload"), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	verifier := trustchain.Verifier{Root: root, Environment: "app-test", ServiceID: "app-server", Audience: "my-app", State: &trustchain.MemoryState{}}
	if e = verifier.Verify(message, proof, nonce, []byte("payload"), time.Now()); e != nil {
		t.Fatal("端到端验签失败", e)
	}
	status, _ = nativeHTTP(t, a, actors[1].cookie, "POST", "/api/trust/app-server/revoke", map[string]any{"version": 1, "reason": "confirmed_leak"})
	if status != 403 {
		t.Fatal("非应急账号撤销", status)
	}
	status, _ = nativeHTTP(t, a, actors[0].cookie, "POST", "/api/trust/app-server/revoke", map[string]any{"version": 1, "reason": "confirmed_leak"})
	if status != 204 {
		t.Fatal("撤销失败", status)
	}
	nonce, _ = trustchain.NewNonce()
	status, raw = nativeHTTP(t, a, actors[0].cookie, "POST", "/api/trust/app-server/status", map[string]string{"nonce": nonce, "audience": "my-app"})
	if status != 200 {
		t.Fatal(status)
	}
	trustchain.DecodeJSON(raw, &proof)
	if !proof.Disabled {
		t.Fatal("撤销后仍发有效状态")
	}
	message, _ = trustchain.SignMessage(root, cert, key, "app-test", "app-server", 1, "my-app", nonce, []byte("payload"), time.Now())
	if verifier.Verify(message, proof, nonce, []byte("payload"), time.Now()) == nil {
		t.Fatal("撤销后客户端仍接受签名")
	}
}

func TestTrustRoutesRegisterTogether(t *testing.T) {
	s := &Service{}
	mux := http.NewServeMux()
	s.trustHistoryRoutes(mux)
	s.trustRoutes(func(pattern string, next http.HandlerFunc) { mux.HandleFunc(pattern, next) })
}
