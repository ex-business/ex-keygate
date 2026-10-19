package webauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestBoundedLogsExcludeRequestSecrets(t *testing.T) {
	var output bytes.Buffer
	s := &Service{logger: slog.New(slog.NewJSONHandler(&output, nil))}
	request := httptest.NewRequest("GET", "https://localhost/auth/callback?code=CODE_SECRET&state=STATE_SECRET", nil)
	request.Header.Set("Authorization", "Bearer TOKEN_SECRET")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: "COOKIE_SECRET"})
	request = request.WithContext(context.WithValue(request.Context(), requestIDKey{}, "req-visible"))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.rejected(request, "token_verify", "identity_claims_invalid", "scope-hash") }()
	}
	wg.Wait()
	if strings.Count(output.String(), "\n") != 1 {
		t.Fatal("rejection logs not rate bounded")
	}
	var first struct {
		Suppressed uint64 `json:"suppressed_count"`
	}
	if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &first) != nil {
		t.Fatal("invalid structured log")
	}
	pending := s.suppressed.Load()
	// Suppressed calls can arrive before or after the logging winner swaps its
	// counter. Account for both destinations instead of assuming a schedule.
	if first.Suppressed+pending != 31 {
		t.Fatal("suppression accounting lost attempts")
	}
	s.lastRejection.Store(0)
	s.rejected(request, "token_verify", "identity_claims_invalid", "scope-hash")
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	var second struct {
		Suppressed uint64 `json:"suppressed_count"`
	}
	if len(lines) != 2 || json.Unmarshal(lines[1], &second) != nil || second.Suppressed != pending || !strings.Contains(output.String(), "req-visible") {
		t.Fatal("trace/suppression metadata missing")
	}
	for _, secret := range []string{"CODE_SECRET", "STATE_SECRET", "TOKEN_SECRET", "COOKIE_SECRET"} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("request secret appeared in logs")
		}
	}
}
func TestServerTraceMatchesAudit(t *testing.T) {
	a := setup(t)
	response := a.request(t, "GET", a.console.URL+"/auth/login", nil, nil, map[string]string{"X-Request-ID": "caller-controlled"})
	readAndClose(t, response)
	id := response.Header.Get("X-Request-ID")
	if !strings.HasPrefix(id, "req-") || id == "caller-controlled" {
		t.Fatal("caller selected audit request ID")
	}
	target, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	stateHash := hash(target.Query().Get("state"))
	var persisted string
	err = a.db.QueryRow("SELECT request_id FROM keygate.audit_events WHERE action='login_create' AND target_id=$1", hex.EncodeToString(stateHash[:])).Scan(&persisted)
	if err != nil || persisted != id {
		t.Fatal("response/audit trace diverged", err)
	}
}
