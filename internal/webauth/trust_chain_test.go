package webauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/storage"
	"ex-keygate/trustchain"
	"fmt"
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
