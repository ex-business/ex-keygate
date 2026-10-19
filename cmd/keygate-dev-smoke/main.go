// The smoke client checks the local protocol flow, not browser SameSite enforcement.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("开发登录烟测失败", "error", err)
		os.Exit(1)
	}
	slog.Info("开发登录烟测通过：可信 TLS、PKCE 登录、会话、CSRF 与持久退出均验证成功")
}
func run() error {
	if e := os.Getenv("KEYGATE_ENV"); e != "" && e != "development" && e != "test" {
		return errors.New("smoke requires development/test")
	}
	var app struct {
		DevelopmentOnly bool
		Origin, CAFile  string
	}
	var sso struct {
		DevelopmentOnly bool
		Issuer, CAFile  string
	}
	if readJSON("data/dev-console/connection.json", &app) != nil || readJSON("data/mock-sso/connection.json", &sso) != nil || !app.DevelopmentOnly || !sso.DevelopmentOnly || !loopback(app.Origin) || !loopback(sso.Issuer) {
		return errors.New("local development metadata invalid")
	}
	origin, _ := url.Parse(app.Origin)
	issuer, _ := url.Parse(sso.Issuer)
	if origin.Hostname() == issuer.Hostname() {
		return errors.New("console and mock must have distinct cookie hosts")
	}
	roots := x509.NewCertPool()
	for _, path := range []string{app.CAFile, sso.CAFile} {
		raw, err := os.ReadFile(path)
		if err != nil || !roots.AppendCertsFromPEM(raw) {
			return errors.New("development CA invalid")
		}
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request := func(method, target string, values url.Values, headers map[string]string) (*http.Response, error) {
		var body io.Reader
		if values != nil {
			body = strings.NewReader(values.Encode())
		}
		req, err := http.NewRequest(method, target, body)
		if err != nil {
			return nil, errors.New("invalid smoke request")
		}
		if values != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		response, err := client.Do(req)
		if err != nil {
			return nil, errors.New("development endpoint request failed")
		}
		return response, nil
	}
	closeResponse := func(response *http.Response) {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32768))
		response.Body.Close()
	}
	response, err := request("GET", app.Origin+"/auth/login", nil, nil)
	if err != nil {
		return err
	}
	closeResponse(response)
	if response.StatusCode != 303 {
		return errors.New("login initialization failed")
	}
	authorize, err := url.Parse(response.Header.Get("Location"))
	if err != nil || authorize.Scheme+"://"+authorize.Host != sso.Issuer {
		return errors.New("unexpected authorization endpoint")
	}
	params := authorize.Query()
	params.Set("subject", "demo-approver-1")
	response, err = request("POST", sso.Issuer+"/authorize", params, map[string]string{"Origin": sso.Issuer})
	if err != nil {
		return err
	}
	closeResponse(response)
	if response.StatusCode != 303 {
		return errors.New("mock authorization failed")
	}
	callback := response.Header.Get("Location")
	target, err := url.Parse(callback)
	if err != nil || target.Scheme+"://"+target.Host != app.Origin {
		return errors.New("unexpected callback target")
	}
	response, err = request("GET", callback, nil, nil)
	if err != nil {
		return err
	}
	closeResponse(response)
	if response.StatusCode != 200 {
		return errors.New("callback failed")
	}
	sessionCookie := false
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-keygate_session" {
			if !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode {
				return errors.New("session cookie unsafe")
			}
			sessionCookie = true
		}
	}
	if !sessionCookie {
		return errors.New("session cookie missing")
	}
	response, err = request("GET", app.Origin+"/auth/session", nil, nil)
	if err != nil {
		return err
	}
	var session struct {
		PrincipalID, CSRFToken string
		ManagementAuthorized   bool
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&session)
	closeResponse(response)
	if err != nil || response.StatusCode != 200 || session.PrincipalID == "" || session.CSRFToken == "" || session.ManagementAuthorized {
		return errors.New("session identity check failed")
	}
	response, err = request("POST", app.Origin+"/auth/logout", nil, map[string]string{"Origin": app.Origin, "X-CSRF-Token": "wrong"})
	if err != nil {
		return err
	}
	closeResponse(response)
	if response.StatusCode != 403 {
		return errors.New("invalid CSRF accepted")
	}
	response, err = request("POST", app.Origin+"/auth/logout", nil, map[string]string{"Origin": app.Origin, "X-CSRF-Token": session.CSRFToken})
	if err != nil {
		return err
	}
	closeResponse(response)
	if response.StatusCode != 204 {
		return errors.New("logout failed")
	}
	response, err = request("GET", app.Origin+"/auth/session", nil, nil)
	if err != nil {
		return err
	}
	closeResponse(response)
	if response.StatusCode != 401 {
		return errors.New("logged-out session accepted")
	}
	return nil
}
func readJSON(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 16384 {
		return errors.New("metadata unavailable")
	}
	return json.Unmarshal(raw, out)
}
func loopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
}
