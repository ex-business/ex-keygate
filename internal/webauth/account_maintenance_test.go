package webauth

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/storage"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAccountBindingHTTPProvesNewFactorAndPreservesRootBudget(t *testing.T) {
	delivery := &testDelivery{sent: map[string]mfa.Delivery{}}
	old := mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.Email, M: 1, N: 1, Required: true}}}
	plan := MFAEnrollmentPlan{WitnessSubjects: [2]string{"demo-requester", "demo-approver-1"}, EvidenceHash: strings.Repeat("a", 64), ApproverSubjects: []string{"demo-approver-1", "demo-approver-2"}, M: 2}
	for _, subject := range []string{"demo-requester", "demo-approver-1", "demo-approver-2"} {
		plan.People = append(plan.People, MFAEnrollmentPerson{Subject: subject, Policy: old, Factors: []MFAEnrollmentFactor{{ID: "mail", Method: mfa.Email, Label: "本人邮件", Reference: subject + "@example.invalid"}}})
	}
	a := setupFlowInitialized(t, true, "", func(c *Config) {
		c.MFAPlugins = mfa.Plugins{Email: delivery}
		c.MFAPluginPolicyHash = strings.Repeat("b", 64)
	}, func(s *Service) {
		if e := s.ProvisionNativeMFAOffline(context.Background(), plan); e != nil {
			t.Fatal(e)
		}
	})
	actors := []businessActor{}
	for _, subject := range []string{"demo-requester", "demo-approver-1", "demo-approver-2"} {
		cookie := nativeLogin(t, a, subject)
		actors = append(actors, businessActor{cookie, csrf(cookie.Value)})
	}
	prove := func(actor businessActor, purpose string) {
		t.Helper()
		if _, e := a.db.Exec(`UPDATE keygate.mfa_policies SET last_started=NULL WHERE environment=$1`, a.service.flow.environment); e != nil {
			t.Fatal(e)
		}
		status, raw := a.business(t, actor, "POST", "/api/mfa/challenges", map[string]string{"purpose": purpose})
		if status != 200 {
			t.Fatal("开始本人验证", status)
		}
		var challenge struct {
			State struct {
				ID string `json:"id"`
			} `json:"state"`
		}
		if json.Unmarshal(raw, &challenge) != nil {
			t.Fatal("挑战响应")
		}
		path := "/api/mfa/challenges/" + challenge.State.ID + "/factors/mail"
		status, raw = a.business(t, actor, "POST", path, struct{}{})
		if status != 201 {
			t.Fatal("准备邮件验证", status)
		}
		var attempt struct {
			ID string `json:"attemptId"`
		}
		json.Unmarshal(raw, &attempt)
		status, _ = a.business(t, actor, "POST", path+"/verify", map[string]string{"code": delivery.code(attempt.ID)})
		if status != 200 {
			t.Fatal("证明本人邮件", status)
		}
	}
	prove(actors[0], "management")
	status, raw := a.business(t, actors[0], "GET", "/api/console/settings", nil)
	var settings storage.ConsoleSettings
	if status != 200 || json.Unmarshal(raw, &settings) != nil {
		t.Fatal("人员目录", status)
	}
	var target storage.ConsolePerson
	for _, p := range settings.People {
		if p.PersonID == "demo-requester" {
			target = p
		}
	}
	revision, _ := strconv.ParseUint(target.Revision, 10, 64)
	token := random()
	h, e := setupHash(token)
	if e != nil {
		t.Fatal(e)
	}
	policy := mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: 1, Required: true}}}
	op := storage.ControlOperation{Kind: storage.MaintainAccount, ClientID: "governance-management", ExpectedRevision: revision, Maintenance: &storage.AccountMaintenance{Target: target.PrincipalID, Mode: "bind", TokenHash: h, PreviousPolicy: &old, Policy: &policy, ResetPassword: true, Username: "synthetic-owner", Reason: "本人受控更换验证器", EvidenceHash: strings.Repeat("c", 64)}}
	r := a.submitOperation(t, actors[0], op)
	for _, actor := range actors[1:] {
		prove(actor, r.ID)
		status, _ = a.business(t, actor, "POST", "/api/requests/"+r.ID+"/votes", map[string]any{"digest": r.Digest, "accept": true})
		if status != 200 {
			t.Fatal("审批", status)
		}
	}
	a.executeHTTP(t, actors[0], r)
	anon := businessActor{}
	status, raw = a.business(t, anon, "POST", "/api/account/setup/factors", map[string]string{"token": token, "method": "totp", "label": "新验证器", "reference": ""})
	if status != 201 {
		t.Fatal("准备新绑定", status)
	}
	var prepared struct {
		Seed   string     `json:"seed"`
		Factor mfa.Factor `json:"factor"`
	}
	if json.Unmarshal(raw, &prepared) != nil || prepared.Seed == "" {
		t.Fatal("没有本人种子")
	}
	var usedBefore, usedAfter int
	if e = a.db.QueryRow(`SELECT used FROM keygate.root_budgets WHERE root_id=$1`, a.service.protector.RootID()).Scan(&usedBefore); e != nil {
		t.Fatal(e)
	}
	status, _ = a.business(t, anon, "POST", "/api/account/setup/factors", map[string]string{"token": token, "method": "totp", "label": "重复候选", "reference": ""})
	if status != 409 {
		t.Fatal("超额候选", status)
	}
	if e = a.db.QueryRow(`SELECT used FROM keygate.root_budgets WHERE root_id=$1`, a.service.protector.RootID()).Scan(&usedAfter); e != nil || usedBefore != usedAfter {
		t.Fatal("超额消耗包装预算", e)
	}
	secret, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(prepared.Seed)
	if e != nil {
		t.Fatal("种子格式")
	}
	defer clear(secret)
	status, _ = a.business(t, anon, "POST", "/api/account/setup/verify", map[string]string{"token": token, "factorId": prepared.Factor.ID, "code": testTOTP(secret, time.Now().Unix()/30)})
	if status != 204 {
		t.Fatal("新因子证明", status)
	}
	status, _ = a.business(t, anon, "POST", "/api/account/setup/complete", map[string]string{"token": token, "newPassword": "synthetic-disposable-password-123"})
	if status != 403 {
		t.Fatal("换绑绕过旧本人MFA", status)
	}
	status, _ = a.business(t, actors[0], "POST", "/api/account/setup/complete", map[string]string{"token": token, "newPassword": "synthetic-disposable-password-123"})
	if status != 204 {
		t.Fatal("完成本人设置", status)
	}
	status, _ = a.business(t, anon, "POST", "/api/account/setup/status", map[string]string{"token": token})
	if status != 403 {
		t.Fatal("复用交付码", status)
	}
	status, _ = a.business(t, actors[0], "GET", "/api/account/self", nil)
	if status != 403 && status != 401 {
		t.Fatal("旧会话仍有效", status)
	}
}
