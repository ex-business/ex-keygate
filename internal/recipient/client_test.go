package recipient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"ex-keygate/internal/manifest"
)

func TestBoundContextAndTransport(t *testing.T) {
	identity, e := Generate()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(identity.Encryption)
	defer clear(identity.Signing)
	var followed atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer destination.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer origin.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	c, e := New(origin.URL, ca, identity)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	scope := Scope{Environment: "demo", ClientID: "backend", IssueID: "issue", Version: 1}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	data := deliveryContext{ClientID: scope.ClientID, Environment: scope.Environment, IssueID: scope.IssueID, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Purpose: "keygate-delivery-claim-v1", EncryptionFingerprint: c.public.EncryptionFingerprint, SigningFingerprint: c.public.SigningFingerprint, Version: "1"}
	raw, _ := manifest.Canonical(data)
	if e = c.context(raw, scope, "keygate-delivery-claim-v1"); e != nil {
		t.Fatal(e)
	}
	for _, scenario := range []string{"target", "purpose", "encryption", "signing", "nonce"} {
		item := data
		switch scenario {
		case "target":
			item.ClientID = "other"
		case "purpose":
			item.Purpose = "other"
		case "encryption":
			item.EncryptionFingerprint = "other"
		case "signing":
			item.SigningFingerprint = "other"
		case "nonce":
			item.Nonce = "AA"
		}
		changed, _ := manifest.Canonical(item)
		if e = c.context(changed, scope, "keygate-delivery-claim-v1"); e == nil {
			t.Fatal("unbound claim", scenario)
		}
	}
	if _, e = c.Claim(context.Background(), scope); e == nil || followed.Load() != 0 {
		t.Fatal("redirect followed")
	}
	for _, bad := range []string{"http://localhost:18761", "https://example.com", "https://localhost/path", "https://localhost#fragment"} {
		if _, e = New(bad, ca, identity); e == nil {
			t.Fatal("unsafe endpoint", bad)
		}
	}
}
