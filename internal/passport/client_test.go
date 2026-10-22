package passport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTransportAndBindingGuards(t *testing.T) {
	secret := "epe_" + strings.Repeat("x", 43)
	for _, endpoint := range []string{"http://example.com", "http://localhost:1234", "https://user:pass@example.com", "https://example.com/path", "https://example.com/?x=1", "ftp://127.0.0.1"} {
		if _, e := New(Config{URL: endpoint, ClientID: "executor", Secret: secret, AllowLoopbackHTTP: true}); !errors.Is(e, ErrInvalid) {
			t.Fatalf("accepted endpoint %s", endpoint)
		}
	}
	if _, e := New(Config{URL: "https://passport.example", ClientID: "executor", Secret: secret, TLS: &tls.Config{InsecureSkipVerify: true}}); e == nil {
		t.Fatal("insecure TLS")
	}
	if _, e := New(Config{URL: "http://127.0.0.1:1", ClientID: "executor", Secret: secret}); e == nil {
		t.Fatal("implicit HTTP")
	}
	b := Request{OperationID: "op", Operation: "rotate", ClientID: "api", ExpectedRevision: 4}
	for _, scenario := range []string{"ok", "bad-hash", "bad-version", "wrong-id", "not-found", "fake-not-found", "redirect", "oversized", "query-auth-failure"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id, key, ok := r.BasicAuth()
				if !ok || id != "executor" || key != secret {
					t.Error("missing dedicated credential")
				}
				result := Result{OperationID: b.OperationID, Operation: b.Operation, ClientID: b.ClientID, Revision: 5, RequestHash: b.Hash(), Replayed: true}
				switch scenario {
				case "bad-hash":
					result.RequestHash = strings.Repeat("a", 64)
				case "bad-version":
					result.Revision++
				case "wrong-id":
					result.OperationID = "other"
				case "not-found":
					w.WriteHeader(404)
					w.Write([]byte(`{"success":false,"code":"EXECUTOR_OPERATION_NOT_FOUND"}`))
					return
				case "fake-not-found":
					w.WriteHeader(404)
					w.Write([]byte(`{"success":false,"code":"OTHER"}`))
					return
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1")
					w.WriteHeader(307)
					return
				case "oversized":
					w.Write([]byte(strings.Repeat("x", 32769)))
					return
				case "query-auth-failure":
					w.WriteHeader(401)
					w.Write([]byte(`{"success":false,"code":"INVALID_CREDENTIALS"}`))
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": result})
			}))
			defer server.Close()
			c, e := New(Config{URL: server.URL, ClientID: "executor", Secret: secret, AllowLoopbackHTTP: true})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_, e = c.Query(context.Background(), b)
			switch scenario {
			case "ok":
				if e != nil {
					t.Fatal(e)
				}
			case "not-found":
				if !errors.Is(e, ErrNotFound) {
					t.Fatal(e)
				}
			case "query-auth-failure":
				if !errors.Is(e, ErrRejected) {
					t.Fatal(e)
				}
			default:
				if !errors.Is(e, ErrUnknown) {
					t.Fatal("accepted unverified result", e)
				}
			}
		})
	}
}
