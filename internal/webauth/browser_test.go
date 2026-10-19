package webauth

import (
	"encoding/json"
	"ex-keygate/internal/storage"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func (a testApp) h5Client(t *testing.T, id string) (businessActor, []businessActor) {
	t.Helper()
	owner := a.loginAs(t, "demo-requester")
	approvers := []businessActor{a.loginAs(t, "demo-approver-1"), a.loginAs(t, "demo-approver-2")}
	r := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.CreateClient, ClientID: id, Name: "H5客户端", ProfileID: "browser", ProfileVersion: 1})
	a.approveHTTP(t, approvers, r)
	a.executeHTTP(t, owner, r)
	return owner, approvers
}
func (a testApp) startH5(t *testing.T, id, subject string) (string, *http.Cookie) {
	t.Helper()
	response := a.request(t, "GET", a.console.URL+"/h5/login/"+id, nil, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 303 {
		t.Fatal("H5登录启动失败", response.StatusCode)
	}
	bound := findCookie(t, response, loginCookie)
	target, e := url.Parse(response.Header.Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	values := target.Query()
	values.Set("subject", subject)
	response = a.request(t, "POST", a.idp.URL+"/authorize", nil, values, map[string]string{"Origin": a.idp.URL})
	readAndClose(t, response)
	if response.StatusCode != 303 {
		t.Fatal(response.StatusCode)
	}
	return response.Header.Get("Location"), bound
}
func (a testApp) h5Call(t *testing.T, method, path string, cookie *http.Cookie, csrfValue, origin string) (int, []byte, *http.Response) {
	t.Helper()
	headers := map[string]string{}
	var body url.Values
	if method == "POST" {
		body = url.Values{}
		headers["Content-Type"] = "application/json"
		headers["Origin"] = origin
		if csrfValue != "" {
			headers["X-CSRF-Token"] = csrfValue
		}
	}
	// request helper 只支持表单，H5 JSON 请求复用 business helper 以保持严格正文契约。
	if method == "POST" {
		actor := businessActor{cookie: cookie, csrf: csrfValue}
		request, e := http.NewRequest(method, a.console.URL+path, strings.NewReader("{}"))
		if e != nil {
			t.Fatal(e)
		}
		if actor.cookie != nil {
			request.AddCookie(actor.cookie)
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, e := a.client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, readAndClose(t, response), response
	}
	response := a.request(t, method, a.console.URL+path, cookie, body, headers)
	return response.StatusCode, readAndClose(t, response), response
}
func TestH5OIDCSessionAuthenticationAndLogout(t *testing.T) {
	a := setupFlow(t, true)
	a.h5Client(t, "h5-one")
	callback, bound := a.startH5(t, "h5-one", "demo-requester")
	response := a.request(t, "GET", callback, bound, nil, nil)
	body := readAndClose(t, response)
	if response.StatusCode != 200 || !strings.Contains(string(body), "/h5?client=h5-one") {
		t.Fatal("H5回调失败", response.StatusCode)
	}
	appCookie := findCookie(t, response, a.service.browserCookie("h5-one"))
	identity := findCookie(t, response, sessionCookie)
	if !appCookie.HttpOnly || !appCookie.Secure || appCookie.Path != "/" || appCookie.Domain != "" || appCookie.SameSite != http.SameSiteStrictMode || appCookie.MaxAge > 300 {
		t.Fatal("H5 Cookie属性不安全")
	}
	status, raw, _ := a.h5Call(t, "GET", "/api/browser/h5-one/session", appCookie, "", "")
	if status != 200 {
		t.Fatal(status)
	}
	var session struct {
		CSRFToken string
		ClientID  string
	}
	if json.Unmarshal(raw, &session) != nil || session.ClientID != "h5-one" || session.CSRFToken == "" {
		t.Fatal("会话响应不正确")
	}
	if strings.Contains(string(raw), appCookie.Value) {
		t.Fatal("JSON泄露HttpOnly会话凭据")
	}
	if status, _, _ := a.h5Call(t, "POST", "/api/browser/h5-one/authenticate", appCookie, session.CSRFToken, a.console.URL); status != 200 {
		t.Fatal(status)
	}
	if status, _, _ := a.h5Call(t, "POST", "/api/browser/h5-one/authenticate", appCookie, "", a.console.URL); status != 403 {
		t.Fatal("缺失CSRF仍通过", status)
	}
	if status, _, _ := a.h5Call(t, "POST", "/api/browser/h5-one/authenticate", appCookie, session.CSRFToken, "https://evil.invalid"); status != 403 {
		t.Fatal("跨域请求仍通过", status)
	}
	if status, _, _ := a.h5Call(t, "GET", "/api/browser/other/session", appCookie, "", ""); status != 401 {
		t.Fatal("H5 Cookie可跨客户端使用", status)
	}
	if status, _ := a.business(t, businessActor{cookie: appCookie}, "GET", "/api/requests", nil); status != 401 {
		t.Fatal("H5 Cookie可用于管理", status)
	}
	response = a.request(t, "GET", callback, bound, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("H5回调可重复消费")
	}
	status, raw, _ = a.h5Call(t, "GET", "/auth/session", identity, "", "")
	if status != 200 {
		t.Fatal(status)
	}
	var auth struct{ CSRFToken string }
	if json.Unmarshal(raw, &auth) != nil {
		t.Fatal("身份响应错误")
	}
	status, _, replaced := a.h5Call(t, "POST", "/api/browser/h5-one/session", identity, auth.CSRFToken, a.console.URL)
	if status != 201 {
		t.Fatal("不能基于已有身份建立H5会话", status)
	}
	newer := findCookie(t, replaced, a.service.browserCookie("h5-one"))
	if status, _, _ := a.h5Call(t, "GET", "/api/browser/h5-one/session", appCookie, "", ""); status != 401 {
		t.Fatal("轮换后旧会话仍有效")
	}
	status, raw, _ = a.h5Call(t, "GET", "/api/browser/h5-one/session", newer, "", "")
	if status != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatal(status)
	}
	status, _, loggedOut := a.h5Call(t, "POST", "/api/browser/h5-one/logout", newer, session.CSRFToken, a.console.URL)
	if status != 204 {
		t.Fatal(status)
	}
	if findCookie(t, loggedOut, a.service.browserCookie("h5-one")).MaxAge != -1 {
		t.Fatal("退出未清理Cookie")
	}
	if status, _, _ := a.h5Call(t, "POST", "/api/browser/h5-one/authenticate", newer, session.CSRFToken, a.console.URL); status != 401 {
		t.Fatal("退出后仍可认证")
	}
	if status, _, _ := a.h5Call(t, "GET", "/auth/session", identity, "", ""); status != 200 {
		t.Fatal("H5退出错误撤销了其他身份会话")
	}
}
func TestH5LoginRechecksDisabledClientAndParentIdentity(t *testing.T) {
	a := setupFlow(t, true)
	owner, _ := a.h5Client(t, "h5-live")
	callback, bound := a.startH5(t, "h5-live", "demo-approver-1")
	response := a.request(t, "GET", callback, bound, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	app := findCookie(t, response, a.service.browserCookie("h5-live"))
	identity := findCookie(t, response, sessionCookie)
	_, raw, _ := a.h5Call(t, "GET", "/api/browser/h5-live/session", app, "", "")
	var session struct{ CSRFToken string }
	if json.Unmarshal(raw, &session) != nil {
		t.Fatal("会话错误")
	}
	_, raw, _ = a.h5Call(t, "GET", "/auth/session", identity, "", "")
	var auth struct{ CSRFToken string }
	if json.Unmarshal(raw, &auth) != nil {
		t.Fatal("身份错误")
	}
	if status, _, _ := a.h5Call(t, "POST", "/auth/logout", identity, auth.CSRFToken, a.console.URL); status != 204 {
		t.Fatal(status)
	}
	if status, _, _ := a.h5Call(t, "POST", "/api/browser/h5-live/authenticate", app, session.CSRFToken, a.console.URL); status != 401 {
		t.Fatal("父身份退出后H5继续放行")
	}
	callback, bound = a.startH5(t, "h5-live", "demo-requester")
	if status, _ := a.business(t, owner, "POST", "/api/clients/h5-live/emergency-disable", struct{}{}); status != 204 {
		t.Fatal(status)
	}
	var before int
	if e := a.db.QueryRow(`SELECT count(*) FROM keygate.sessions`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	response = a.request(t, "GET", callback, bound, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("在途停用仍建立H5会话", response.StatusCode)
	}
	var after int
	if e := a.db.QueryRow(`SELECT count(*) FROM keygate.sessions`).Scan(&after); e != nil {
		t.Fatal(e)
	}
	if after != before {
		t.Fatal("失败回调遗留父身份会话")
	}
	for _, value := range response.Cookies() {
		if value.Name == sessionCookie && value.MaxAge > 0 {
			t.Fatal("失败回调下发父身份Cookie")
		}
	}
	for _, value := range response.Cookies() {
		if value.Name == a.service.browserCookie("h5-live") && value.MaxAge > 0 {
			t.Fatal("失败回调仍签发H5 Cookie")
		}
	}
}
func TestH5RejectsNonBrowserProfilesAndUnsafeRoutes(t *testing.T) {
	a := setupFlow(t, true)
	owner, _ := a.h5Client(t, "h5-valid")
	r := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.CreateClient, ClientID: "backend-other", Name: "Backend", ProfileID: "backend", ProfileVersion: 1})
	a.approveHTTP(t, []businessActor{a.loginAs(t, "demo-approver-1"), a.loginAs(t, "demo-approver-2")}, r)
	a.executeHTTP(t, owner, r)
	response := a.request(t, "GET", a.console.URL+"/h5/login/backend-other", nil, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 403 {
		t.Fatal("后端Profile被H5执行器接受", response.StatusCode)
	}
	cfg := a.service.config
	cfg.BrowserReturnPaths = map[string]string{"h5-valid": "//evil.invalid"}
	if _, e := New(cfg, a.store, a.service.protector); e == nil {
		t.Fatal("跨站返回地址被接受")
	}
	for _, path := range []string{"/h5", "/h5.js", "/sdk/browser.js"} {
		response = a.request(t, "GET", a.console.URL+path, nil, nil, nil)
		readAndClose(t, response)
		if response.StatusCode != 200 {
			t.Fatal(path, response.StatusCode)
		}
	}
}

func TestH5CallbackAuditFailureLeavesNoPartialSessions(t *testing.T) {
	a := setupFlow(t, true)
	a.h5Client(t, "h5-atomic")
	callback, bound := a.startH5(t, "h5-atomic", "demo-requester")
	var before int
	if e := a.db.QueryRow(`SELECT count(*) FROM keygate.sessions`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	name := "h5_fault_" + hexToken()
	if _, e := a.db.Exec(`ALTER TABLE keygate.audit_events ADD CONSTRAINT ` + name + ` CHECK(action<>'browser_session_create' OR target_id<>'h5-atomic')`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := a.db.Exec(`ALTER TABLE keygate.audit_events DROP CONSTRAINT ` + name); e != nil {
			t.Error(e)
		}
	})
	response := a.request(t, "GET", callback, bound, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 503 {
		t.Fatal(response.StatusCode)
	}
	for _, value := range response.Cookies() {
		if value.MaxAge > 0 && (value.Name == sessionCookie || value.Name == a.service.browserCookie("h5-atomic")) {
			t.Fatal("审计失败下发有效凭据")
		}
	}
	var after int
	if e := a.db.QueryRow(`SELECT count(*) FROM keygate.sessions`).Scan(&after); e != nil {
		t.Fatal(e)
	}
	if after != before {
		t.Fatal("失败回调未回滚父会话")
	}
	if e := a.db.QueryRow(`SELECT count(*) FROM keygate.browser_sessions WHERE environment=$1`, a.service.flow.environment).Scan(&after); e != nil || after != 0 {
		t.Fatal("失败回调未回滚H5会话", e)
	}
}
