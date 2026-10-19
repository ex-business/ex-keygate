package webauth

import (
	"ex-keygate/internal/identity"
	"strings"
	"testing"
)

func TestAdminLoginRequestsFreshAuthentication(t *testing.T) {
	a := setup(t)
	response := a.request(t, "GET", a.console.URL+"/auth/login", nil, nil, nil)
	readAndClose(t, response)
	location := response.Header.Get("Location")
	if response.StatusCode != 303 || !strings.Contains(location, "max_age=0") || !strings.Contains(location, "prompt=login") {
		t.Fatal("管理登录没有要求重新认证")
	}
}
func TestAdminCallbackRejectsOldAuthentication(t *testing.T) {
	a := setup(t)
	callback, browser := a.start(t)
	// 将可信开始时间前移到未来，模拟 IdP 返回早于本次登录窗口的缓存认证结果。
	if _, e := a.db.Exec(`UPDATE keygate.login_states SET started_at=clock_timestamp()+interval '90 seconds' WHERE browser_hash=$1`, hashBytes(browser.Value)); e != nil {
		t.Fatal(e)
	}
	response := a.request(t, "GET", callback, browser, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("旧认证绕过了管理重新认证", response.StatusCode)
	}
	for _, c := range response.Cookies() {
		if c.Name == sessionCookie && c.MaxAge > 0 {
			t.Fatal("失败后仍签发管理会话")
		}
	}
}
func hashBytes(value string) []byte { h := hash(value); return h[:] }
func TestCallbackRequiresConfiguredAuthenticationMethods(t *testing.T) {
	a := setup(t)
	c := a.service.config.Identity
	c.RequiredAMR = []string{"pwd", "otp"}
	verifier, e := identity.NewOIDC(c)
	if e != nil {
		t.Fatal(e)
	}
	// 模拟 IdP 只声明 mock，不能满足 pwd+otp 的真实策略。
	a.service.verifier = verifier
	callback, browser := a.start(t)
	response := a.request(t, "GET", callback, browser, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("不满足认证方式仍创建会话", response.StatusCode)
	}
}
func TestConfidentialClientConfiguration(t *testing.T) {
	a := setup(t)
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		c := a.service.config
		c.TokenAuthMethod = method
		c.ClientSecret = "development-test-only"
		s, e := New(c, a.store, a.service.protector)
		if e != nil || s.oauth.ClientSecret != c.ClientSecret {
			t.Fatal("confidential client rejected", e)
		}
	}
	for _, tc := range []struct{ method, secret string }{{"none", "unexpected"}, {"client_secret_basic", ""}, {"auto", "value"}} {
		c := a.service.config
		c.TokenAuthMethod = tc.method
		c.ClientSecret = tc.secret
		if _, e := New(c, a.store, a.service.protector); e == nil {
			t.Fatal("无效客户端认证配置被接受")
		}
	}
}
