package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
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
	return LoginState{StateHash: state, BrowserHash: browser, ProfileHash: hex.EncodeToString(profile[:]), Nonce: base64.RawURLEncoding.EncodeToString(browser[:]), VerifierCipher: []byte("encrypted-verifier")}, Audit{unique(t), "request", "anonymous", "login_create", hex.EncodeToString(state[:]), "pending"}
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
	profile := strings.Repeat("a", 64)
	hash := sha256.Sum256([]byte(unique(t)))
	target := hex.EncodeToString(hash[:])
	event := unique(t)
	a := Audit{event, "request", "operator", "session_create", target, "success"}
	session, err := s.CreateSession(ctx, hash, profile, "operator", time.Now().Add(-time.Minute), a)
	if err != nil {
		t.Fatal(err)
	}
	if session.ExpiresAt.Sub(session.AuthenticatedAt) > 5*time.Minute {
		t.Fatal("session lifetime extended")
	}
	if _, err = other.Session(ctx, hash, profile); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, hash, strings.Repeat("b", 64)); !errors.Is(err, ErrSession) {
		t.Fatal("foreign profile accepted", err)
	}
	revoke := Audit{event, "request", "operator", "session_revoke", target, "revoked"}
	if err = s.RevokeSession(ctx, hash, profile, revoke); err == nil {
		t.Fatal("audit conflict allowed revocation")
	}
	if _, err = s.Session(ctx, hash, profile); err != nil {
		t.Fatal("revocation failed to roll back", err)
	}
	revoke.EventID = unique(t)
	if err = other.RevokeSession(ctx, hash, profile, revoke); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, hash, profile); !errors.Is(err, ErrSession) {
		t.Fatal("revoked session accepted", err)
	}
	expired := sha256.Sum256([]byte(unique(t)))
	a.EventID = unique(t)
	a.TargetID = hex.EncodeToString(expired[:])
	if _, err = s.CreateSession(ctx, expired, profile, "operator", time.Now().Add(-6*time.Minute), a); !errors.Is(err, ErrSession) {
		t.Fatal("stale authentication accepted", err)
	}
	fresh := sha256.Sum256([]byte(unique(t)))
	a.EventID = unique(t)
	a.TargetID = hex.EncodeToString(fresh[:])
	if _, err = s.CreateSession(ctx, fresh, profile, "operator", time.Now(), a); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE keygate.sessions SET expires_at=clock_timestamp()-interval '1 second',authenticated_at=clock_timestamp()-interval '1 minute' WHERE token_hash=$1", fresh[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Session(ctx, fresh, profile); !errors.Is(err, ErrSession) {
		t.Fatal("expired session accepted", err)
	}
}

func TestLegacyUnboundSessionsRevoked(t *testing.T) {
	s, db := database(t)
	ctx := context.Background()
	h := sha256.Sum256([]byte(unique(t)))
	zero := strings.Repeat("0", 64)
	_, err := db.Exec(`INSERT INTO keygate.sessions(token_hash,principal_id,authenticated_at,expires_at,profile_hash) VALUES($1,'legacy',clock_timestamp(),clock_timestamp()+interval '1 minute',$2)`, h[:], zero)
	if err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(ctx, h, zero); !errors.Is(err, ErrSession) {
		t.Fatal("legacy session survived migration", err)
	}
}

// 已完成迁移后的重复校验不能为了旧 DDL 阻塞正在使用的有效会话行。
func TestRepeatedMigrationAvoidsDDLOnActiveSessionTable(t *testing.T) {
	s, db := database(t)
	ctx := context.Background()
	h := sha256.Sum256([]byte(unique(t)))
	profile := strings.Repeat("a", 64)
	if _, e := s.CreateSession(ctx, h, profile, "migration-fixture", time.Now().Add(-time.Second), Audit{unique(t), unique(t), "migration-fixture", "session_create", hex.EncodeToString(h[:]), "success"}); e != nil {
		t.Fatal(e)
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	var raw []byte
	if e = tx.QueryRowContext(ctx, `SELECT token_hash FROM keygate.sessions WHERE token_hash=$1 FOR UPDATE`, h[:]).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if e = Migrate(bounded, db); e != nil {
		t.Fatal("重复迁移仍尝试锁定会话表DDL", e)
	}
}
