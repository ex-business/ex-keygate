package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func loginFixture(t *testing.T) (LoginState, Audit) {
	t.Helper()
	state := sha256.Sum256([]byte(unique(t)))
	browser := sha256.Sum256([]byte(unique(t)))
	profile := sha256.Sum256([]byte(unique(t)))
	return LoginState{state, browser, hex.EncodeToString(profile[:]), base64.RawURLEncoding.EncodeToString(browser[:]), []byte("encrypted-verifier")}, Audit{unique(t), "request", "anonymous", "login_create", hex.EncodeToString(state[:]), "pending"}
}
func TestAtomicBrowserBoundLogin(t *testing.T) {
	s, db := database(t)
	other, _ := New(db)
	ctx := context.Background()
	state, a := loginFixture(t)
	if err := s.CreateLogin(ctx, state, a); err != nil {
		t.Fatal(err)
	}
	consume := func(event string) Audit {
		return Audit{event, "request", "anonymous", "login_consume", a.TargetID, "consumed"}
	}
	wrong := sha256.Sum256([]byte("other"))
	if _, err := s.ConsumeLogin(ctx, state.StateHash, wrong, state.ProfileHash, consume(unique(t))); !errors.Is(err, ErrLogin) {
		t.Fatal(err)
	}
	if _, err := s.ConsumeLogin(ctx, state.StateHash, state.BrowserHash, hex.EncodeToString(wrong[:]), consume(unique(t))); !errors.Is(err, ErrLogin) {
		t.Fatal(err)
	}
	if _, err := s.ConsumeLogin(ctx, state.StateHash, state.BrowserHash, state.ProfileHash, consume(a.EventID)); err == nil {
		t.Fatal("audit failure consumed login")
	}
	var count atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			node := s
			if i%2 == 1 {
				node = other
			}
			_, err := node.ConsumeLogin(ctx, state.StateHash, state.BrowserHash, state.ProfileHash, consume(unique(t)))
			if err == nil {
				count.Add(1)
			} else if !errors.Is(err, ErrLogin) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal("login reused", count.Load())
	}
	expired, b := loginFixture(t)
	if err := s.CreateLogin(ctx, expired, b); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE keygate.login_states SET expires_at=clock_timestamp()-interval '1 second' WHERE state_hash=$1", expired.StateHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeLogin(ctx, expired.StateHash, expired.BrowserHash, expired.ProfileHash, Audit{unique(t), "request", "anonymous", "login_consume", b.TargetID, "consumed"}); !errors.Is(err, ErrLogin) {
		t.Fatal("expired login accepted", err)
	}
}
func TestSessionExpiryRevocationAndAudit(t *testing.T) {
	s, db := database(t)
	other, _ := New(db)
	ctx := context.Background()
	hash := sha256.Sum256([]byte(unique(t)))
	target := hex.EncodeToString(hash[:])
	event := unique(t)
	a := Audit{event, "request", "operator", "session_create", target, "success"}
	session, err := s.CreateSession(ctx, hash, "operator", time.Now().Add(-time.Minute), a)
	if err != nil {
		t.Fatal(err)
	}
	if session.ExpiresAt.Sub(session.AuthenticatedAt) > 5*time.Minute {
		t.Fatal("session lifetime extended")
	}
	if _, err = other.Session(ctx, hash); err != nil {
		t.Fatal(err)
	}
	revoke := Audit{event, "request", "operator", "session_revoke", target, "revoked"}
	if err = s.RevokeSession(ctx, hash, revoke); err == nil {
		t.Fatal("audit conflict allowed revocation")
	}
	if _, err = s.Session(ctx, hash); err != nil {
		t.Fatal("revocation failed to roll back", err)
	}
	revoke.EventID = unique(t)
	if err = other.RevokeSession(ctx, hash, revoke); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, hash); !errors.Is(err, ErrSession) {
		t.Fatal("revoked session accepted", err)
	}
	expired := sha256.Sum256([]byte(unique(t)))
	a.EventID = unique(t)
	a.TargetID = hex.EncodeToString(expired[:])
	if _, err = s.CreateSession(ctx, expired, "operator", time.Now().Add(-6*time.Minute), a); !errors.Is(err, ErrSession) {
		t.Fatal("stale authentication accepted", err)
	}
	fresh := sha256.Sum256([]byte(unique(t)))
	a.EventID = unique(t)
	a.TargetID = hex.EncodeToString(fresh[:])
	if _, err = s.CreateSession(ctx, fresh, "operator", time.Now(), a); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE keygate.sessions SET expires_at=clock_timestamp()-interval '1 second',authenticated_at=clock_timestamp()-interval '1 minute' WHERE token_hash=$1", fresh[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Session(ctx, fresh); !errors.Is(err, ErrSession) {
		t.Fatal("expired session accepted", err)
	}
}
