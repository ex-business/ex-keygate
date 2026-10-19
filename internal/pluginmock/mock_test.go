package pluginmock

import (
	"bytes"
	"encoding/json"
	"ex-keygate/provider"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMockRejectsAmbiguousAndInvalidRequests(t *testing.T) {
	m, e := New()
	if e != nil {
		t.Fatal(e)
	}
	payload, proof := m.Vector()
	raw, e := json.Marshal(provider.WireVerification{ProtocolVersion: "1", ProviderID: ID, ProviderVersion: "1", RequestID: "request-1", Environment: "test", ClientID: "conformance", Audience: "conformance", Purpose: "conformance", Key: provider.KeyReference{ID: "mock-conformance", Version: 1}, Algorithm: "ed25519", Payload: payload, Proof: proof})
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{[]byte(strings.Replace(string(raw), `"clientId"`, `"ClientId"`, 1)), []byte(strings.Replace(string(raw), `"id":"mock-conformance"`, `"ID":"mock-conformance"`, 1)), []byte(strings.Replace(string(raw), `"clientId":"conformance"`, `"clientId":"\ud800"`, 1)), bytes.Replace(raw, []byte(`"clientId":"conformance"`), []byte{'"', 'c', 'l', 'i', 'e', 'n', 't', 'I', 'd', '"', ':', '"', 0xff, '"'}, 1)} {
		r := httptest.NewRequest("POST", "https://localhost/v1/verify", bytes.NewReader(bad))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("非法请求未拒绝", w.Code)
		}
	}
}
