package passport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJWTResultMustMatchApprovalPayloadAndVersion(t *testing.T) {
	b := JWTRequest{OperationID: "operation", ApprovalDigest: strings.Repeat("a", 64), Operation: "revoke", Kid: "old", ExpectedRevision: 10, Reason: "confirmed leak"}
	for _, scenario := range []string{"valid", "digest", "hash", "version", "kid", "secret", "notfound", "fake404"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				out := Result{OperationID: b.OperationID, ApprovalDigest: b.ApprovalDigest, Operation: b.Operation, Kid: b.Kid, Revision: 11, RequestHash: b.Hash(), Replayed: true}
				switch scenario {
				case "digest":
					out.ApprovalDigest = strings.Repeat("b", 64)
				case "hash":
					out.RequestHash = strings.Repeat("b", 64)
				case "version":
					out.Revision++
				case "kid":
					out.Kid = "other"
				case "secret":
					out.ClientSecret = "unexpected-secret"
				case "notfound":
					w.WriteHeader(404)
					w.Write([]byte(`{"success":false,"code":"EXECUTOR_OPERATION_NOT_FOUND"}`))
					return
				case "fake404":
					w.WriteHeader(404)
					w.Write([]byte(`{"success":false,"code":"NOT_FOUND"}`))
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "OK", "data": out})
			}))
			defer server.Close()
			client, e := New(Config{URL: server.URL, ClientID: "jwt", Secret: "epe_" + strings.Repeat("j", 43), AllowLoopbackHTTP: true})
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			_, e = client.QueryJWT(context.Background(), b)
			if scenario == "valid" {
				if e != nil {
					t.Fatal(e)
				}
			} else if scenario == "notfound" {
				if !errors.Is(e, ErrNotFound) {
					t.Fatal(e)
				}
			} else if !errors.Is(e, ErrUnknown) {
				t.Fatal("unbound confirmation accepted", e)
			}
		})
	}
}
