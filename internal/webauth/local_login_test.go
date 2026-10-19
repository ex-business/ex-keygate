package webauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/password"
	"ex-keygate/internal/storage"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLocalLoginRequiresCSRFAndMFA(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	encoded, _ := password.Hash("test-local-secret-123456")
	plan := MFAEnrollmentPlan{WitnessSubjects: [2]string{"demo-requester", "demo-approver-1"}, EvidenceHash: strings.Repeat("c", 64), ApproverSubjects: []string{"demo-approver-1", "demo-approver-2"}, M: 2}
	for _, subject := range []string{"demo-requester", "demo-approver-1", "demo-approver-2"} {
		seed := make([]byte, 32)
		rand.Read(seed)
		if subject == "demo-requester" {
			seed = secret
		}
		plan.People = append(plan.People, MFAEnrollmentPerson{Subject: subject, Policy: mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: 1, Required: true}}}, Factors: []MFAEnrollmentFactor{{ID: "otp", Method: mfa.TOTP, Label: "动态码", TOTPSeed: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)}}})
	}
	a := setupFlowInitialized(t, true, "", nil, func(s *Service) {
		if e := s.ProvisionNativeMFAOffline(context.Background(), plan); e != nil {
			t.Fatal(e)
		}
		if e := s.ProvisionLocalAccountsOffline(context.Background(), LocalAccountPlan{Accounts: []LocalAccountEnrollment{{"operator", "demo-requester", encoded}}}); e != nil {
			t.Fatal(e)
		}
	})
	response := a.request(t, "GET", a.console.URL+"/manage", nil, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 303 || response.Header.Get("Location") != "/login" {
		t.Fatal("匿名入口未进入登录页")
	}
	response = a.request(t, "GET", a.console.URL+"/auth/options", nil, nil, nil)
	raw := readAndClose(t, response)
	var options struct {
		CSRFToken string `json:"csrfToken"`
	}
	json.Unmarshal(raw, &options)
	var prelogin *http.Cookie
	for _, c := range response.Cookies() {
		if c.Name == passwordCSRFCookie {
			prelogin = c
		}
	}
	if prelogin == nil {
		t.Fatal("缺少登录CSRF")
	}
	post := func(value, origin, csrfValue string) *http.Response {
		raw, _ := json.Marshal(map[string]string{"username": "operator", "password": value})
		r, _ := http.NewRequest("POST", a.console.URL+"/auth/password", bytes.NewReader(raw))
		r.AddCookie(prelogin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrfValue)
		out, e := a.client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	for _, values := range [][2]string{{"https://attacker.invalid", options.CSRFToken}, {a.console.URL, "bad"}} {
		response = post("test-local-secret-123456", values[0], values[1])
		readAndClose(t, response)
		if response.StatusCode != 403 {
			t.Fatal("登录CSRF被绕过")
		}
	}
	response = post("wrong-password", a.console.URL, options.CSRFToken)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("错误密码被接收")
	}
	response = post("test-local-secret-123456", a.console.URL, options.CSRFToken)
	readAndClose(t, response)
	if response.StatusCode != 200 {
		t.Fatal("口令登录失败", response.StatusCode)
	}
	var session *http.Cookie
	for _, c := range response.Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil {
		t.Fatal("缺少待验证会话")
	}
	status, _ := nativeHTTP(t, a, session, "GET", "/api/config", nil)
	if status != 403 {
		t.Fatal("未验证会话获得权限")
	}
	status, raw = nativeHTTP(t, a, session, "POST", "/api/mfa/challenges", map[string]string{"purpose": "management"})
	if status != 200 {
		t.Fatal("MFA启动失败", status)
	}
	var result struct {
		State struct {
			ID string `json:"id"`
		} `json:"state"`
	}
	json.Unmarshal(raw, &result)
	path := "/api/mfa/challenges/" + result.State.ID + "/factors/otp"
	status, _ = nativeHTTP(t, a, session, "POST", path, struct{}{})
	if status != 201 {
		t.Fatal("MFA准备失败", status)
	}
	status, _ = nativeHTTP(t, a, session, "POST", path+"/verify", map[string]string{"code": testTOTP(secret, time.Now().Unix()/30)})
	if status != 200 {
		t.Fatal("MFA失败", status)
	}
	status, _ = nativeHTTP(t, a, session, "GET", "/api/config", nil)
	if status != 200 {
		t.Fatal("完整登录后权限失败", status)
	}
	// 旧节点不认识密码来源标记，必须通过配置摘要版本隔离新会话，防止滚动升级期间绕过MFA。
	c := a.service.config
	legacyValues := []any{c.MFAPluginPolicyHash, "admin-fresh-login-v1", c.Identity.RequiredAMR, c.TokenAuthMethod, c.Identity.Issuer, c.Identity.JWKSURL, c.Identity.ClientID, c.Identity.AllowedACR, c.Identity.MaxAuthAge, c.AuthorizationEndpoint, c.TokenEndpoint, c.CallbackURL, c.PolicyVersion, c.Environment, a.service.protector.RootID()}
	legacyRaw, _ := json.Marshal(legacyValues)
	legacyHash := sha256.Sum256(legacyRaw)
	legacyProfile := hex.EncodeToString(legacyHash[:])
	if legacyProfile == a.service.profile {
		t.Fatal("旧节点仍可认领新密码会话")
	}
	if _, e := a.store.Session(context.Background(), hash(session.Value), legacyProfile); !errors.Is(e, storage.ErrSession) {
		t.Fatal("旧身份配置接受新密码会话", e)
	}

}
