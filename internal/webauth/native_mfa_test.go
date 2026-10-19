package webauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"ex-keygate/internal/mfa"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type testDelivery struct {
	calls int
	mu    sync.Mutex
	sent  map[string]mfa.Delivery
	deny  bool
}

func (p *testDelivery) Send(_ context.Context, d mfa.Delivery) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deny {
		return mfa.ErrPlugin
	}
	p.calls++
	p.sent[d.ID] = d
	return nil
}
func (p *testDelivery) code(id string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent[id].Code
}

type testHardware struct {
	key        ed25519.PublicKey
	mu         sync.Mutex
	challenges map[string]mfa.HardwareChallenge
}

func (p *testHardware) Begin(_ context.Context, c mfa.HardwareChallenge) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.challenges[c.ID] = c
	return json.RawMessage(`{"developmentOnly":true}`), nil
}
func (p *testHardware) Verify(_ context.Context, c mfa.HardwareChallenge, proof json.RawMessage) error {
	var value struct {
		Signature string `json:"signature"`
	}
	if json.Unmarshal(proof, &value) != nil {
		return mfa.ErrInvalid
	}
	signature, e := base64.RawURLEncoding.DecodeString(value.Signature)
	raw, _ := json.Marshal(c)
	if e != nil || !ed25519.Verify(p.key, raw, signature) {
		return mfa.ErrInvalid
	}
	return nil
}
func nativeHTTP(t *testing.T, a testApp, cookie *http.Cookie, method, path string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, e := http.NewRequest(method, a.console.URL+path, reader)
	if e != nil {
		t.Fatal(e)
	}
	req.AddCookie(cookie)
	if method == "POST" {
		req.Header.Set("Origin", a.console.URL)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf(cookie.Value))
		req.Header.Set("X-Idempotency-Key", hexToken())
	}
	response, e := a.client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	return response.StatusCode, readAndClose(t, response)
}
func nativeLogin(t *testing.T, a testApp, subject string) *http.Cookie {
	t.Helper()
	callback, browser := a.startAs(t, subject)
	response := a.request(t, "GET", callback, browser, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 200 {
		t.Fatal("登录失败", response.StatusCode)
	}
	return findCookie(t, response, sessionCookie)
}
func TestNativeFourMethodsMustAllPassBeforeManagementAccess(t *testing.T) {
	delivery := &testDelivery{sent: map[string]mfa.Delivery{}}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	hardware := &testHardware{key: public, challenges: map[string]mfa.HardwareChallenge{}}
	seeds := map[string][]byte{}
	plan := MFAEnrollmentPlan{WitnessSubjects: [2]string{"demo-requester", "demo-approver-1"}, EvidenceHash: strings.Repeat("c", 64), ApproverSubjects: []string{"demo-approver-1", "demo-approver-2"}, M: 2}
	for _, subject := range []string{"demo-requester", "demo-approver-1", "demo-approver-2"} {
		secret := make([]byte, 32)
		rand.Read(secret)
		seeds[subject] = secret
		person := MFAEnrollmentPerson{Subject: subject, Policy: mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: 1, Required: true}}}, Factors: []MFAEnrollmentFactor{{ID: "otp", Method: mfa.TOTP, Label: "动态码", TOTPSeed: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)}}}
		if subject == "demo-approver-1" {
			person.Policy.M = 4
			person.Policy.Rules = append(person.Policy.Rules, mfa.Rule{Method: mfa.Email, M: 1, N: 1, Required: true}, mfa.Rule{Method: mfa.SMS, M: 1, N: 1, Required: true}, mfa.Rule{Method: mfa.Hardware, M: 1, N: 1, Required: true})
			person.Factors = append(person.Factors, MFAEnrollmentFactor{ID: "mail", Method: mfa.Email, Label: "邮件", Reference: "one@example.invalid"}, MFAEnrollmentFactor{ID: "phone", Method: mfa.SMS, Label: "短信", Reference: "+12025550123"}, MFAEnrollmentFactor{ID: "key", Method: mfa.Hardware, Label: "硬件", Reference: base64.RawURLEncoding.EncodeToString(public)})
		}
		plan.People = append(plan.People, person)
	}
	a := setupFlowInitialized(t, true, "", func(c *Config) {
		c.MFAPlugins = mfa.Plugins{Email: delivery, SMS: delivery, Hardware: hardware}
		c.MFAPluginPolicyHash = strings.Repeat("a", 64)
	}, func(s *Service) {
		if e := s.ProvisionNativeMFAOffline(context.Background(), plan); e != nil {
			t.Fatal(e)
		}
	})
	cookie := nativeLogin(t, a, "demo-approver-1")
	status, _ := nativeHTTP(t, a, cookie, "GET", "/api/config", nil)
	if status != 403 {
		t.Fatal("未验证的管理请求被放行", status)
	}
	status, raw := nativeHTTP(t, a, cookie, "POST", "/api/mfa/challenges", map[string]string{"purpose": "management"})
	if status != 200 {
		t.Fatal("创建验证失败", status, string(raw))
	}
	var result struct {
		State struct {
			ID        string `json:"id"`
			Completed bool   `json:"completed"`
		} `json:"state"`
	}
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("响应无效")
	}
	challenge := result.State.ID
	for _, factor := range []string{"mail", "phone", "otp", "key"} {
		path := "/api/mfa/challenges/" + challenge + "/factors/" + factor
		status, raw = nativeHTTP(t, a, cookie, "POST", path, struct{}{})
		if status != 201 {
			t.Fatal("准备验证失败", factor, status, string(raw))
		}
		var attempt struct {
			ID string `json:"attemptId"`
		}
		json.Unmarshal(raw, &attempt)
		if factor == "mail" {
			var usedBefore, usedAfter int64
			if e := a.db.QueryRow(`SELECT used FROM keygate.root_budgets WHERE root_id=$1`, a.service.protector.RootID()).Scan(&usedBefore); e != nil {
				t.Fatal(e)
			}
			repeatedStatus, repeatedRaw := nativeHTTP(t, a, cookie, "POST", path, struct{}{})
			var repeated struct {
				ID string `json:"attemptId"`
			}
			json.Unmarshal(repeatedRaw, &repeated)
			delivery.mu.Lock()
			calls := delivery.calls
			delivery.mu.Unlock()
			if e := a.db.QueryRow(`SELECT used FROM keygate.root_budgets WHERE root_id=$1`, a.service.protector.RootID()).Scan(&usedAfter); e != nil {
				t.Fatal(e)
			}
			if repeatedStatus != 201 || repeated.ID != attempt.ID || calls != 1 || usedBefore != usedAfter {
				t.Fatal("重复准备触发了重发或替换投递ID")
			}
		}
		var proof any
		switch factor {
		case "mail", "phone":
			code := delivery.code(attempt.ID)
			if code == "" || strings.Contains(string(raw), code) {
				t.Fatal("验证码未发送或泄露到响应")
			}
			proof = map[string]string{"code": code}
		case "otp":
			proof = map[string]string{"code": testTOTP(seeds["demo-approver-1"], time.Now().Unix()/30)}
		case "key":
			hardware.mu.Lock()
			c := hardware.challenges[attempt.ID]
			hardware.mu.Unlock()
			message, _ := json.Marshal(c)
			proof = map[string]any{"proof": map[string]string{"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}}
		}
		if factor == "mail" || factor == "key" {
			wrong := any(map[string]string{"code": "not-code"})
			if factor == "key" {
				wrong = map[string]any{"proof": map[string]string{"signature": "invalid"}}
			}
			denied, _ := nativeHTTP(t, a, cookie, "POST", path+"/verify", wrong)
			if denied != 403 {
				t.Fatal("错误验证通过", factor, denied)
			}
		}
		status, raw = nativeHTTP(t, a, cookie, "POST", path+"/verify", proof)
		if status != 200 {
			t.Fatal("验证失败", factor, status, string(raw))
		}
		json.Unmarshal(raw, &result)
		if result.State.Completed != (factor == "key") {
			t.Fatal("多种组合提前通过", factor)
		}
	}
	status, _ = nativeHTTP(t, a, cookie, "GET", "/api/config", nil)
	if status != 200 {
		t.Fatal("组合完成后仍未放行", status)
	}
	// 完成后重交相同绑定不会再次计数，其他人的会话不能读取本人的验证过程。
	status, _ = nativeHTTP(t, a, cookie, "POST", "/api/mfa/challenges/"+challenge+"/factors/mail/verify", map[string]string{"code": "00000000"})
	if status == 200 {
		t.Fatal("完成后仍能重复计数")
	}
	other := nativeLogin(t, a, "demo-approver-2")
	status, _ = nativeHTTP(t, a, other, "GET", "/api/mfa/challenges/"+challenge, nil)
	if status != 403 {
		t.Fatal("串人读取验证状态", status)
	}
}
func testTOTP(secret []byte, counter int64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(counter))
	h := hmac.New(sha1.New, secret)
	h.Write(b[:])
	sum := h.Sum(nil)
	o := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
