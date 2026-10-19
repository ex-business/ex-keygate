package storage

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ex-keygate/internal/httpsign"
)

func signedProbe(t *testing.T, f keyFixture, secret []byte, body []byte) (*http.Request, httpsign.Message) {
	t.Helper()
	now := time.Now().Unix()
	m := httpsign.Message{ClientID: "one", Environment: f.f.c.environment, Audience: "keygate-probe", RequestID: unique(t), Version: 1, Created: now, Expires: now + 60}
	if _, e := rand.Read(m.Nonce[:]); e != nil {
		t.Fatal(e)
	}
	r, e := http.NewRequest("POST", "https://localhost:18761/api/auth/probe", strings.NewReader(string(body)))
	if e != nil {
		t.Fatal(e)
	}
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	if e = httpsign.Sign(r, body, secret, m); e != nil {
		t.Fatal(e)
	}
	return r, m
}
func TestActualAuthenticationLifecycle(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	bundle, secret := f.claim(t, r)
	defer clear(secret)
	body := []byte(`{"probe":true}`)
	request, _ := signedProbe(t, f, secret, body)
	if e := f.k.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
		t.Fatal("pending key authenticated")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(bundle.PossessionInput)
	if e := f.k.ConfirmPossession(ctx, r.ID, mac.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	request, _ = signedProbe(t, f, secret, body)
	if e := f.k.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
		t.Fatal("staged key authenticated")
	}
	f.operation(t, ActivateKey, 1, "")
	request, _ = signedProbe(t, f, secret, body)
	if e := f.k.AuthenticateProbe(ctx, request, body, "keygate-probe"); e != nil {
		t.Fatal("active key rejected", e)
	}
	if e := f.k.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
		t.Fatal("replay accepted")
	}
	request, _ = signedProbe(t, f, secret, body)
	if e := f.k.AuthenticateProbe(ctx, request, []byte(`{"probe":false}`), "keygate-probe"); e == nil {
		t.Fatal("body swap accepted")
	}
	if e := f.k.AuthenticateProbe(ctx, request, body, "other-audience"); e == nil {
		t.Fatal("wrong audience")
	}
	// 同一签名通过多个实例并发验证，也只能消费一次 nonce。
	var wg sync.WaitGroup
	var successes atomic.Int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := f.k.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("cross-node replay accepted", successes.Load())
	}
	f.operation(t, DisableKey, 1, "")
	request, _ = signedProbe(t, f, secret, body)
	if e := f.k.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
		t.Fatal("disabled key authenticated")
	}
}
func TestAuthTimeAndDependencyDenials(t *testing.T) {
	for _, scenario := range []string{"expired-signature", "future-signature", "profile", "root", "client", "key-expired", "database", "http"} {
		t.Run(scenario, func(t *testing.T) {
			f := newKeyFixture(t)
			ctx := context.Background()
			r := f.issue(t, 1)
			bundle, secret := f.claim(t, r)
			defer clear(secret)
			mac := hmac.New(sha256.New, secret)
			mac.Write(bundle.PossessionInput)
			if e := f.k.ConfirmPossession(ctx, r.ID, mac.Sum(nil), unique(t)); e != nil {
				t.Fatal(e)
			}
			f.operation(t, ActivateKey, 1, "")
			body := []byte(`{}`)
			request, m := signedProbe(t, f, secret, body)
			switch scenario {
			case "expired-signature":
				m.Created = time.Now().Unix() - 120
				m.Expires = m.Created + 60
				_ = httpsign.Sign(request, body, secret, m)
			case "future-signature":
				m.Created = time.Now().Unix() + 120
				m.Expires = m.Created + 60
				_ = httpsign.Sign(request, body, secret, m)
			case "profile":
				_, _ = f.f.db.Exec(`UPDATE keygate.auth_profiles SET enabled=false WHERE environment=$1`, f.f.c.environment)
			case "root":
				_, _ = f.f.db.Exec(`UPDATE keygate.client_roots SET enabled=false WHERE environment=$1`, f.f.c.environment)
			case "client":
				if e := f.f.c.EmergencyDisableClient(ctx, f.f.tokens[0], "one", unique(t)); e != nil {
					t.Fatal(e)
				}
			case "key-expired":
				_, _ = f.f.db.Exec(`UPDATE keygate.key_versions SET not_before=clock_timestamp()-interval '2 hours',not_after=clock_timestamp()-interval '1 second' WHERE environment=$1`, f.f.c.environment)
			case "database":
				_ = f.f.db.Close()
			case "http":
				request.TLS = nil
			}
			if e := f.k.AuthenticateProbe(ctx, request, body, "keygate-probe"); e == nil {
				t.Fatal("authentication failed open")
			}
		})
	}
}
