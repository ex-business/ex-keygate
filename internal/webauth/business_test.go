package webauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ex-keygate/internal/access"
	"ex-keygate/internal/httpsign"
	"ex-keygate/internal/storage"
)

type businessActor struct {
	cookie *http.Cookie
	csrf   string
}

func (a testApp) loginAs(t *testing.T, subject string) businessActor {
	t.Helper()
	callback, browser := a.startAs(t, subject)
	response := a.request(t, "GET", callback, browser, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 200 {
		t.Fatal("login callback failed")
	}
	cookie := findCookie(t, response, sessionCookie)
	response = a.request(t, "GET", a.console.URL+"/auth/session", cookie, nil, nil)
	var data struct {
		CSRFToken            string
		ManagementAuthorized bool
	}
	if e := json.Unmarshal(readAndClose(t, response), &data); e != nil || !data.ManagementAuthorized {
		t.Fatal("local permission not connected", e)
	}
	return businessActor{cookie, data.CSRFToken}
}
func (a testApp) business(t *testing.T, actor businessActor, method, path string, data any) (int, []byte) {
	t.Helper()
	var raw []byte
	if data != nil {
		var e error
		raw, e = json.Marshal(data)
		if e != nil {
			t.Fatal(e)
		}
	}
	request, e := http.NewRequest(method, a.console.URL+path, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if actor.cookie != nil {
		request.AddCookie(actor.cookie)
	}
	if method == "POST" {
		request.Header.Set("Origin", a.console.URL)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", actor.csrf)
		request.Header.Set("X-Idempotency-Key", hexToken())
	}
	response, e := a.client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	return response.StatusCode, readAndClose(t, response)
}
func (a testApp) submitOperation(t *testing.T, actor businessActor, op storage.ControlOperation) storage.ControlRequest {
	t.Helper()
	status, raw := a.business(t, actor, "POST", "/api/requests", op)
	if status != 201 {
		t.Fatalf("submit failed %d %s", status, raw)
	}
	var r storage.ControlRequest
	if e := json.Unmarshal(raw, &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func (a testApp) approveHTTP(t *testing.T, actors []businessActor, r storage.ControlRequest) {
	t.Helper()
	for _, actor := range actors {
		status, raw := a.business(t, actor, "POST", "/api/requests/"+r.ID+"/votes", map[string]any{"digest": r.Digest, "accept": true})
		if status != 200 {
			t.Fatalf("vote failed %d %s", status, raw)
		}
	}
}
func (a testApp) executeHTTP(t *testing.T, actor businessActor, r storage.ControlRequest) {
	t.Helper()
	status, raw := a.business(t, actor, "POST", "/api/requests/"+r.ID+"/execute", map[string]string{"digest": r.Digest})
	if status != 200 {
		t.Fatalf("execute failed %d %s", status, raw)
	}
}
func (a testApp) currentClient(t *testing.T, actor businessActor) access.Client {
	t.Helper()
	status, raw := a.business(t, actor, "GET", "/api/clients/backend-one", nil)
	if status != 200 {
		t.Fatal("client read failed", status)
	}
	var c access.Client
	if e := json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	return c
}
func (a testApp) probe(t *testing.T, secret []byte, environment string, expected int, replay bool) {
	t.Helper()
	body := []byte(`{"probe":true}`)
	now := time.Now().Unix()
	m := httpsign.Message{ClientID: "backend-one", Environment: environment, Audience: probeAudience, RequestID: hexToken(), Version: 1, Created: now, Expires: now + 60}
	if _, e := rand.Read(m.Nonce[:]); e != nil {
		t.Fatal(e)
	}
	request, e := http.NewRequest("POST", a.console.URL+"/api/auth/probe", bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if e = httpsign.Sign(request, body, secret, m); e != nil {
		t.Fatal(e)
	}
	response, e := a.client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	readAndClose(t, response)
	if response.StatusCode != expected {
		t.Fatal("probe status", response.StatusCode, expected)
	}
	if replay {
		request.Body = ioNopBody(body)
		response, e = a.client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		readAndClose(t, response)
		if response.StatusCode != 401 {
			t.Fatal("HTTP replay accepted", response.StatusCode)
		}
	}
}
func ioNopBody(raw []byte) io.ReadCloser { return io.NopCloser(bytes.NewReader(raw)) }

func TestHTTPClientKeyFlow(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	alice := a.loginAs(t, "demo-approver-1")
	bob := a.loginAs(t, "demo-approver-2")
	approvers := []businessActor{alice, bob}
	create := storage.ControlOperation{Kind: storage.CreateClient, ClientID: "backend-one", Name: "后端认证客户端", ProfileID: "backend", ProfileVersion: 1}
	if status, _ := a.business(t, businessActor{}, "POST", "/api/requests", create); status != 401 {
		t.Fatal("anonymous management access", status)
	}
	if status, _ := a.business(t, alice, "POST", "/api/requests", create); status != 403 {
		t.Fatal("approver became requester", status)
	}
	r := a.submitOperation(t, owner, create)
	if status, _ := a.business(t, owner, "POST", "/api/requests/"+r.ID+"/votes", map[string]any{"digest": r.Digest, "accept": true}); status != 403 {
		t.Fatal("self approval", status)
	}
	if status, _ := a.business(t, owner, "POST", "/api/requests/"+r.ID+"/execute", map[string]string{"digest": r.Digest}); status != 403 {
		t.Fatal("unapproved execution", status)
	}
	a.approveHTTP(t, approvers, r)
	if status, _ := a.business(t, alice, "POST", "/api/requests/"+r.ID+"/execute", map[string]string{"digest": r.Digest}); status != 403 {
		t.Fatal("approver triggered requester execution", status)
	}
	a.executeHTTP(t, owner, r)
	client := a.currentClient(t, owner)
	encryption, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		t.Fatal(e)
	}
	public, signing, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	encryptionDER, _ := x509.MarshalPKIXPublicKey(&encryption.PublicKey)
	signingDER, _ := x509.MarshalPKIXPublicKey(public)
	eh := sha256.Sum256(encryptionDER)
	sh := sha256.Sum256(signingDER)
	issue := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.IssueKey, ClientID: client.ID, ExpectedRevision: client.Revision, KeyVersion: 1, RootID: a.service.flow.rootID, RecipientPublicKey: base64.RawStdEncoding.EncodeToString(encryptionDER), RecipientFingerprint: hex.EncodeToString(eh[:]), RecipientSigningKey: base64.RawStdEncoding.EncodeToString(signingDER), RecipientSigningFingerprint: hex.EncodeToString(sh[:]), NotAfter: time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")})
	a.approveHTTP(t, approvers, issue)
	a.executeHTTP(t, owner, issue)
	status, raw := a.business(t, businessActor{}, "GET", "/api/deliveries/"+issue.ID+"/challenge", nil)
	if status != 200 {
		t.Fatal("challenge failed", status)
	}
	var challenge struct{ Input []byte }
	if e = json.Unmarshal(raw, &challenge); e != nil {
		t.Fatal(e)
	}
	status, raw = a.business(t, businessActor{}, "POST", "/api/deliveries/"+issue.ID+"/claim", map[string]any{"signature": ed25519.Sign(signing, challenge.Input)})
	if status != 200 {
		t.Fatal("claim failed", status, string(raw))
	}
	var bundle storage.DeliveryBundle
	if e = json.Unmarshal(raw, &bundle); e != nil {
		t.Fatal(e)
	}
	secret, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, encryption, bundle.Ciphertext, bundle.OAEPLabel)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(secret)
	a.probe(t, secret, a.service.flow.environment, 401, false)
	mac := hmac.New(sha256.New, secret)
	mac.Write(bundle.PossessionInput)
	if status, _ = a.business(t, businessActor{}, "POST", "/api/deliveries/"+issue.ID+"/confirm", map[string]any{"mac": mac.Sum(nil)}); status != 204 {
		t.Fatal("possession failed", status)
	}
	a.probe(t, secret, a.service.flow.environment, 401, false)
	client = a.currentClient(t, owner)
	activate := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.ActivateKey, ClientID: client.ID, ExpectedRevision: client.Revision, KeyVersion: 1})
	a.approveHTTP(t, approvers, activate)
	a.executeHTTP(t, owner, activate)
	a.probe(t, secret, a.service.flow.environment, 200, true)
	client = a.currentClient(t, owner)
	disable := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.DisableKey, ClientID: client.ID, ExpectedRevision: client.Revision, KeyVersion: 1})
	a.approveHTTP(t, approvers, disable)
	a.executeHTTP(t, owner, disable)
	a.probe(t, secret, a.service.flow.environment, 401, false)
	status, raw = a.business(t, owner, "GET", "/api/clients/backend-one/keys/1", nil)
	if status != 200 || !bytes.Contains(raw, []byte("disabled")) {
		t.Fatal("disabled state unavailable", status)
	}
}
func TestManagementHTTPBoundaries(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	for _, raw := range []string{`{"kind":"client_create","kind":"key_issue"}`, `{"kind":"client_create","Kind":"key_issue"}`, `{"actor":"admin"}`, `{"name":"\ud800"}`, `null`, `{} {}`} {
		request, e := http.NewRequest("POST", a.console.URL+"/api/requests", strings.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		request.AddCookie(owner.cookie)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", a.console.URL)
		request.Header.Set("X-CSRF-Token", owner.csrf)
		request.Header.Set("X-Idempotency-Key", hexToken())
		response, e := a.client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		readAndClose(t, response)
		if response.StatusCode != 400 {
			t.Fatal("ambiguous JSON accepted", response.StatusCode)
		}
	}
	for _, origin := range []string{"", "https://attacker.invalid"} {
		request, e := http.NewRequest("POST", a.console.URL+"/api/requests", strings.NewReader(`{}`))
		if e != nil {
			t.Fatal(e)
		}
		request.AddCookie(owner.cookie)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", owner.csrf)
		response, e := a.client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		readAndClose(t, response)
		if response.StatusCode != 403 {
			t.Fatal("cross-origin accepted", response.StatusCode)
		}
	}
	defaultApp := setup(t)
	response := defaultApp.request(t, "GET", defaultApp.console.URL+"/api/clients", nil, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 404 {
		t.Fatal("default enabled management")
	}
	response = a.request(t, "GET", a.console.URL+"/manage", owner.cookie, nil, nil)
	html := readAndClose(t, response)
	if response.StatusCode != 200 || !bytes.Contains(html, []byte("/manage.js")) || !bytes.Contains(html, []byte(`id="key-state"`)) {
		t.Fatal("management page absent")
	}
}

func TestStrictCaseSensitiveFields(t *testing.T) {
	for _, raw := range []string{`{"accept":true,"Accept":false}`, `{"Digest":"x","accept":true}`} {
		r := httptest.NewRequest("POST", "https://localhost", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		var input struct {
			Digest string `json:"digest"`
			Accept *bool  `json:"accept"`
		}
		if e := strictJSON(httptest.NewRecorder(), r, &input); e == nil {
			t.Fatal("case alias accepted")
		}
	}
}
