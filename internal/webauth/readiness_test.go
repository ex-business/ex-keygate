package webauth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/recipient"
	"ex-keygate/internal/storage"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestReadinessRequiresBusinessRootsAndAuthoritativeDatabase(t *testing.T) {
	a := setupFlow(t, true)
	owner := a.loginAs(t, "demo-requester")
	get := func(path string, want int) {
		t.Helper()
		r := a.request(t, "GET", a.console.URL+path, nil, nil, nil)
		readAndClose(t, r)
		if r.StatusCode != want {
			t.Fatal(path, r.StatusCode, want)
		}
	}
	get("/health/live", 200)
	get("/health/ready", 200)
	f := a.service.flow
	f.mu.Lock()
	old := f.roots
	f.roots = nil
	f.mu.Unlock()
	get("/health/ready", 503)
	get("/health/live", 200)
	f.mu.Lock()
	f.roots = old
	f.mu.Unlock()
	status, _ := a.business(t, owner, http.MethodPost, "/api/providers/internal-software/disable", struct{}{})
	if status != 200 {
		t.Fatal(status)
	}
	get("/health/ready", 503)
	if e := a.db.Close(); e != nil {
		t.Fatal(e)
	}
	get("/health/ready", 503)
	get("/health/live", 200)
}
func TestLoginOnlyServiceIsNotBusinessReady(t *testing.T) {
	a := setup(t)
	r := a.request(t, "GET", a.console.URL+"/health/ready", nil, nil, nil)
	readAndClose(t, r)
	if r.StatusCode != 503 {
		t.Fatal(r.StatusCode)
	}
}
func TestAttachRejectsWrongRootWithoutReopeningBootstrap(t *testing.T) {
	a := setupFlow(t, true)
	s, e := New(a.service.config, a.store, a.service.protector)
	if e != nil {
		t.Fatal(e)
	}
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if e = s.AttachSimulatedNode(context.Background(), a.service.flow.environment, []DevelopmentRoot{{ID: a.service.flow.rootID, Material: raw}}); e == nil {
		t.Fatal("错误根加入已有域")
	}
	if s.flow != nil {
		t.Fatal("失败的加入留下可运行状态")
	}
}

// 成功加入必须沿用既有身份与授权；实际跨节点会话和请求认证不能重新初始化权限或预算。
func TestAttachExistingDomainServesSharedSessionAndAuthentication(t *testing.T) {
	a := setupFlow(t, true)
	ctx := context.Background()
	owner := a.loginAs(t, "demo-requester")
	approvers := []businessActor{a.loginAs(t, "demo-approver-1"), a.loginAs(t, "demo-approver-2")}
	material, e := keycrypto.Generate()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(material)
	root := "attach-" + hexToken()
	trace := "attach-budget-" + hexToken()
	if e = a.store.RegisterRootBudget(ctx, root, 1000, storage.Audit{EventID: trace, RequestID: trace, ActorID: "offline-bootstrap", Action: "root_budget_register", TargetID: root, Result: "success"}); e != nil {
		t.Fatal(e)
	}
	keys, e := storage.NewDevelopmentKeys(a.service.flow.control, root, material, a.service.protector.RootID())
	if e != nil {
		t.Fatal(e)
	}
	if e = keys.RegisterRootOffline(ctx, "attach-root-"+hexToken()); e != nil {
		t.Fatal(e)
	}
	if _, e = a.db.Exec(`UPDATE keygate.client_roots SET enabled=false WHERE root_id=$1`, a.service.flow.rootID); e != nil {
		t.Fatal(e)
	}
	a.service.flow.mu.Lock()
	a.service.flow.roots = map[string]*storage.DevelopmentKeys{root: keys}
	a.service.flow.keys = keys
	a.service.flow.rootID = root
	a.service.flow.mu.Unlock()
	snapshot := func() string {
		var value string
		e := a.db.QueryRow(`SELECT jsonb_build_array((SELECT count(*) FROM keygate.principals WHERE environment=$1),(SELECT count(*) FROM keygate.role_grants WHERE environment=$1),(SELECT count(*) FROM keygate.root_budgets),(SELECT sum(used) FROM keygate.root_budgets),(SELECT sum(maximum) FROM keygate.root_budgets))::text`, a.service.flow.environment).Scan(&value)
		if e != nil {
			t.Fatal(e)
		}
		return value
	}
	before := snapshot()
	joined, e := New(a.service.config, a.store, a.service.protector)
	if e != nil {
		t.Fatal(e)
	}
	if e = joined.AttachSimulatedNode(ctx, a.service.flow.environment, []DevelopmentRoot{{ID: root, Material: material}}); e != nil {
		t.Fatal(e)
	}
	if e = joined.ConfigureDevelopmentPlugins(ctx, ""); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(joined.ClosePlugins)
	server := httptest.NewTLSServer(joined.Handler())
	t.Cleanup(server.Close)
	peer := a
	peer.service = joined
	// 模拟同一公开入口切到另一后端：只改变实际拨号目标，保留公开 Host、Origin 和签名 authority。
	publicURL, e := url.Parse(a.console.URL)
	if e != nil {
		t.Fatal(e)
	}
	peerRoots := x509.NewCertPool()
	peerRoots.AddCert(server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: peerRoots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != publicURL.Host {
			return nil, errors.New("测试拨号目标不在允许列表")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	peer.client = &http.Client{Transport: transport, Timeout: 5 * time.Second}
	if status, _ := peer.business(t, owner, "GET", "/api/config", nil); status != 200 {
		t.Fatal("已有节点会话未被接受", status)
	}
	response := peer.request(t, "GET", a.console.URL+"/health/ready", nil, nil, nil)
	readAndClose(t, response)
	if response.StatusCode != 200 {
		t.Fatal("加入后未就绪", response.StatusCode)
	}
	if snapshot() != before {
		t.Fatal("加入已有域改写了人员、授权或预算")
	}
	cold, e := New(a.service.config, a.store, a.service.protector)
	if e != nil {
		t.Fatal(e)
	}
	_ = cold.Handler()
	if cold.AttachSimulatedNode(ctx, a.service.flow.environment, []DevelopmentRoot{{ID: root, Material: material}}) == nil || cold.EnableSimulatedFlow(ctx) == nil || cold.ResumeQuarantinedSimulatedFlow(ctx, a.service.flow.environment) == nil {
		t.Fatal("Handler创建后仍可替换安全域")
	}
	// 原节点完成审批、交付和启用，加入节点用同一根直接验证真实请求。
	created := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.CreateClient, ClientID: "backend-one", Name: "跨节点认证", ProfileID: "backend", ProfileVersion: 1})
	a.approveHTTP(t, approvers, created)
	a.executeHTTP(t, owner, created)
	identity, e := recipient.Generate()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(identity.Encryption)
	defer clear(identity.Signing)
	public, e := recipient.Public(identity)
	if e != nil {
		t.Fatal(e)
	}
	client := a.currentClient(t, owner)
	issue := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.IssueKey, ClientID: client.ID, ExpectedRevision: client.Revision, KeyVersion: 1, RootID: root, RecipientPublicKey: public.Encryption, RecipientFingerprint: public.EncryptionFingerprint, RecipientSigningKey: public.Signing, RecipientSigningFingerprint: public.SigningFingerprint, NotAfter: time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")})
	a.approveHTTP(t, approvers, issue)
	a.executeHTTP(t, owner, issue)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.console.Certificate().Raw})
	connection, e := recipient.New(a.console.URL, ca, identity)
	if e != nil {
		t.Fatal(e)
	}
	defer connection.Close()
	credential, e := connection.Claim(ctx, recipient.Scope{Environment: a.service.flow.environment, ClientID: client.ID, IssueID: issue.ID, Version: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(credential.Secret)
	if e = connection.Confirm(ctx, credential); e != nil {
		t.Fatal(e)
	}
	client = a.currentClient(t, owner)
	activation := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.ActivateKey, ClientID: client.ID, ExpectedRevision: client.Revision, KeyVersion: 1})
	a.approveHTTP(t, approvers, activation)
	a.executeHTTP(t, owner, activation)
	peer.probe(t, credential.Secret, a.service.flow.environment, 200, true)
	if status, _ := a.business(t, owner, "POST", "/api/clients/backend-one/emergency-disable", struct{}{}); status != 204 {
		t.Fatal(status)
	}
	peer.probe(t, credential.Secret, a.service.flow.environment, 401, false)
}
