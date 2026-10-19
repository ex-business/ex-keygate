package webauth

import (
	"context"
	"encoding/pem"
	"testing"
	"time"

	"ex-keygate/internal/recipient"
	"ex-keygate/internal/storage"
)

// 通过实际 TLS HTTP 接口验证接收方库；管理端与接收方分别持有身份和私钥，不共享秘密通道。
func TestRecipientLibraryHTTPFlow(t *testing.T) {
	a := setupFlow(t, true)
	ctx := context.Background()
	owner := a.loginAs(t, "demo-requester")
	approvers := []businessActor{a.loginAs(t, "demo-approver-1"), a.loginAs(t, "demo-approver-2")}
	created := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.CreateClient, ClientID: "backend-one", Name: "Recipient library", ProfileID: "backend", ProfileVersion: 1})
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
	issue := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.IssueKey, ClientID: client.ID, ExpectedRevision: client.Revision, KeyVersion: 1, RootID: a.service.flow.rootID, RecipientPublicKey: public.Encryption, RecipientFingerprint: public.EncryptionFingerprint, RecipientSigningKey: public.Signing, RecipientSigningFingerprint: public.SigningFingerprint, NotAfter: time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")})
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
	if status, e := connection.Probe(ctx, credential); e != nil || status != 401 {
		t.Fatal("unconfirmed client authenticated", status, e)
	}
	if e = connection.Confirm(ctx, credential); e != nil {
		t.Fatal(e)
	}
	client = a.currentClient(t, owner)
	activate := a.submitOperation(t, owner, storage.ControlOperation{Kind: storage.ActivateKey, ClientID: client.ID, ExpectedRevision: client.Revision, KeyVersion: 1})
	a.approveHTTP(t, approvers, activate)
	a.executeHTTP(t, owner, activate)
	if status, e := connection.Probe(ctx, credential); e != nil || status != 200 {
		t.Fatal("recipient request not authenticated", status, e)
	}
	if status, _ := a.business(t, owner, "POST", "/api/clients/"+client.ID+"/emergency-disable", struct{}{}); status != 204 {
		t.Fatal("emergency disable", status)
	}
	if status, e := connection.Probe(ctx, credential); e != nil || status != 401 {
		t.Fatal("disabled client authenticated", status, e)
	}
}
