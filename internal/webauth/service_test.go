package webauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ex-keygate/internal/config"
	"ex-keygate/internal/identity"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/keyservice"
	"ex-keygate/internal/mocksso"
	"ex-keygate/internal/storage"
)

type testApp struct {
	console, idp *httptest.Server
	client       *http.Client
	store        *storage.Store
	db           *sql.DB
	service      *Service
}

func setup(t *testing.T) testApp {
	t.Helper()
	dsn := os.Getenv("KEYGATE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	if !strings.Contains(dsn, "/keygate_test?") {
		t.Fatal("invalid test database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open database failed")
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	if err = storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, _ := storage.New(db)
	root := "root-" + hexToken()
	key, _ := keycrypto.Generate()
	if err = store.RegisterRootBudget(ctx, root, 1000, storage.Audit{EventID: root, RequestID: "bootstrap", ActorID: "bootstrap", Action: "root_budget_register", TargetID: root, Result: "success"}); err != nil {
		t.Fatal(err)
	}
	protector, err := keyservice.NewDevelopment(config.Test, root, key, store)
	if err != nil {
		t.Fatal(err)
	}
	console := httptest.NewUnstartedServer(nil)
	idp := httptest.NewUnstartedServer(nil)
	consoleURL := "https://" + console.Listener.Addr().String()
	idpURL := "https://" + idp.Listener.Addr().String()
	mock, err := mocksso.New(mocksso.Config{Environment: "test", Issuer: idpURL, RedirectURI: consoleURL + "/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	idp.Config.Handler = mock.Handler()
	idp.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	idp.StartTLS()
	t.Cleanup(idp.Close)
	roots := x509.NewCertPool()
	roots.AddCert(idp.Certificate())
	service, err := New(Config{Environment: config.Test, Identity: identity.Config{Issuer: idpURL, JWKSURL: idpURL + "/jwks", ClientID: mocksso.ClientID, AllowedACR: []string{mocksso.SimulatedACR}, MaxAuthAge: 5 * time.Minute, TrustedRoots: roots, DevelopmentMode: true}, AuthorizationEndpoint: idpURL + "/authorize", TokenEndpoint: idpURL + "/token", CallbackURL: consoleURL + "/auth/callback", PolicyVersion: 1}, store, protector)
	if err != nil {
		t.Fatal(err)
	}
	console.Config.Handler = service.Handler()
	console.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	console.StartTLS()
	t.Cleanup(console.Close)
	roots.AddCert(console.Certificate())
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	return testApp{console, idp, client, store, db, service}
}
func (a testApp) request(t *testing.T, method, target string, cookie *http.Cookie, body url.Values, headers map[string]string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(body.Encode())
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	response, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func readAndClose(t *testing.T, r *http.Response) []byte {
	t.Helper()
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func findCookie(t *testing.T, r *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range r.Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatal("cookie missing", name)
	return nil
}
func (a testApp) start(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	response := a.request(t, "GET", a.console.URL+"/auth/login", nil, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 303 {
		t.Fatal("login start failed", response.StatusCode)
	}
	cookie := findCookie(t, response, loginCookie)
	if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe login cookie")
	}
	authorization, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	values := authorization.Query()
	values.Set("subject", "demo-approver-1")
	response = a.request(t, "POST", a.idp.URL+"/authorize", nil, values, map[string]string{"Origin": a.idp.URL})
	readAndClose(t, response)
	if response.StatusCode != 303 {
		t.Fatal("mock authorize failed", response.StatusCode)
	}
	return response.Header.Get("Location"), cookie
}
func TestBrowserLoginSessionAndLogout(t *testing.T) {
	a := setup(t)
	callback, browser := a.start(t)
	wrong := *browser
	wrong.Value = random()
	response := a.request(t, "GET", callback, &wrong, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("browser mismatch accepted")
	}
	response = a.request(t, "GET", callback, browser, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 200 {
		t.Fatal("callback failed", response.StatusCode)
	}
	session := findCookie(t, response, sessionCookie)
	if !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteStrictMode || session.MaxAge > 300 {
		t.Fatal("unsafe session cookie")
	}
	response = a.request(t, "GET", callback, browser, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("callback replay accepted")
	}
	response = a.request(t, "GET", a.console.URL+"/auth/session", session, nil, nil)
	body := readAndClose(t, response)
	if response.StatusCode != 200 {
		t.Fatal("session rejected")
	}
	var info struct {
		PrincipalID          string
		CSRFToken            string
		ManagementAuthorized bool
	}
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatal(err)
	}
	if info.PrincipalID == "" || info.CSRFToken == "" || info.ManagementAuthorized {
		t.Fatal("identity granted permissions")
	}
	for _, headers := range []map[string]string{{"Origin": "https://attacker.invalid", "X-CSRF-Token": info.CSRFToken}, {"Origin": a.console.URL}, {"Origin": a.console.URL, "X-CSRF-Token": "wrong"}} {
		response = a.request(t, "POST", a.console.URL+"/auth/logout", session, nil, headers)
		readAndClose(t, response)
		if response.StatusCode != 403 {
			t.Fatal("CSRF logout accepted")
		}
	}
	response = a.request(t, "POST", a.console.URL+"/auth/logout", session, nil, map[string]string{"Origin": a.console.URL, "X-CSRF-Token": info.CSRFToken})
	readAndClose(t, response)
	if response.StatusCode != 204 {
		t.Fatal("logout failed", response.StatusCode)
	}
	response = a.request(t, "GET", a.console.URL+"/auth/session", session, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("revoked session accepted")
	}
}
func TestConcurrentCallbackAndTamperedState(t *testing.T) {
	a := setup(t)
	callback, browser := a.start(t)
	tampered, _ := url.Parse(callback)
	values := tampered.Query()
	values.Set("state", random())
	tampered.RawQuery = values.Encode()
	response := a.request(t, "GET", tampered.String(), browser, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("tampered state accepted")
	}
	var success atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := a.request(t, "GET", callback, browser, nil, nil)
			readAndClose(t, response)
			if response.StatusCode == 200 {
				success.Add(1)
			} else if response.StatusCode != 401 {
				t.Error("unexpected callback result", response.StatusCode)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("callback consumed more than once", success.Load())
	}
}
func TestExpiredLoginAndCorruptVerifierDeny(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "ciphertext"}[corrupt], func(t *testing.T) {
			a := setup(t)
			callback, browser := a.start(t)
			parsed, _ := url.Parse(callback)
			stateHash := hash(parsed.Query().Get("state"))
			sql := "UPDATE keygate.login_states SET expires_at=clock_timestamp()-interval '1 second' WHERE state_hash=$1"
			expected := 401
			if corrupt {
				sql = "UPDATE keygate.login_states SET verifier_cipher=$2 WHERE state_hash=$1"
				expected = 503
			}
			var err error
			if corrupt {
				_, err = a.db.Exec(sql, stateHash[:], []byte(`{}`))
			} else {
				_, err = a.db.Exec(sql, stateHash[:])
			}
			if err != nil {
				t.Fatal(err)
			}
			response := a.request(t, "GET", callback, browser, nil, nil)
			readAndClose(t, response)
			if response.StatusCode != expected {
				t.Fatal("invalid login accepted", response.StatusCode)
			}
			if len(response.Cookies()) > 0 {
				for _, c := range response.Cookies() {
					if c.Name == sessionCookie {
						t.Fatal("invalid verifier issued session")
					}
				}
			}
		})
	}
}
func TestDuplicateCookiesAndQueryRejected(t *testing.T) {
	a := setup(t)
	callback, browser := a.start(t)
	request, _ := http.NewRequest("GET", callback, nil)
	request.AddCookie(browser)
	request.AddCookie(browser)
	response, err := a.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("duplicate cookie accepted")
	}
	response = a.request(t, "GET", callback+"&state="+random(), browser, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 400 {
		t.Fatal("duplicate state accepted")
	}
	if _, err = New(Config{Environment: config.Production}, nil, nil); err == nil {
		t.Fatal("development flow accepted production")
	}
	// A valid-looking bearer header never substitutes for a session cookie.
	response = a.request(t, "GET", a.console.URL+"/auth/session", nil, nil, map[string]string{"Authorization": "Bearer " + random()})
	readAndClose(t, response)
	if response.StatusCode != 401 {
		t.Fatal("bearer accepted as session")
	}
	h := sha256.Sum256([]byte("unused"))
	if _, err = a.store.Session(context.Background(), h, a.service.profile); err == nil {
		t.Fatal("unknown session accepted")
	}
}
