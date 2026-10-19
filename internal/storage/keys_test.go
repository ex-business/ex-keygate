package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ex-keygate/internal/keycrypto"
)

type keyFixture struct {
	signer                         ed25519.PrivateKey
	signingKey, signingFingerprint string
	f                              controlFixture
	k                              *DevelopmentKeys
	recipient                      *rsa.PrivateKey
	encoded, fingerprint           string
}

func newKeyFixture(t *testing.T) keyFixture {
	t.Helper()
	f := newControlFixture(t)
	ctx := context.Background()
	r := submitClient(t, f, "one")
	approveControl(t, f, r)
	if e := f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	root := unique(t)
	material, e := keycrypto.Generate()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(material)
	if e = f.c.store.RegisterRootBudget(ctx, root, 1000, Audit{unique(t), unique(t), "offline-bootstrap", "root_budget_register", root, "success"}); e != nil {
		t.Fatal(e)
	}
	k, e := NewDevelopmentKeys(f.c, root, material, "login-root")
	if e != nil {
		t.Fatal(e)
	}
	if e = k.RegisterRootOffline(ctx, unique(t)); e != nil {
		t.Fatal(e)
	}
	recipient, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(&recipient.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	public, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signingDER, e := x509.MarshalPKIXPublicKey(public)
	if e != nil {
		t.Fatal(e)
	}
	return keyFixture{f: f, k: k, recipient: recipient, encoded: base64.RawStdEncoding.EncodeToString(der), fingerprint: digestBytes(der), signer: signer, signingKey: base64.RawStdEncoding.EncodeToString(signingDER), signingFingerprint: digestBytes(signingDER)}
}
func (f keyFixture) issue(t *testing.T, version uint64) ControlRequest {
	t.Helper()
	ctx := context.Background()
	client, e := f.f.c.Client(ctx, f.f.tokens[0], "one")
	if e != nil {
		t.Fatal(e)
	}
	r, e := f.f.c.Submit(ctx, f.f.tokens[0], ControlOperation{Kind: IssueKey, ClientID: "one", ExpectedRevision: client.Revision, KeyVersion: version, RootID: f.k.rootID, RecipientPublicKey: f.encoded, RecipientFingerprint: f.fingerprint, RecipientSigningKey: f.signingKey, RecipientSigningFingerprint: f.signingFingerprint, NotAfter: time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")}, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	approveControl(t, f.f, r)
	if e = f.k.ExecuteIssue(ctx, r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	return r
}
func (f keyFixture) claim(t *testing.T, r ControlRequest) (DeliveryBundle, []byte) {
	t.Helper()
	ctx := context.Background()
	challenge, e := f.f.c.DeliveryChallenge(ctx, r.ID)
	if e != nil {
		t.Fatal(e)
	}
	signature := ed25519.Sign(f.signer, challenge)
	bundle, e := f.f.c.ClaimDelivery(ctx, r.ID, signature, unique(t))
	if e != nil {
		t.Fatal(e)
	}
	secret, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.recipient, bundle.Ciphertext, bundle.OAEPLabel)
	if e != nil || len(secret) != 32 {
		t.Fatal("delivery decryption", e)
	}
	if _, e = f.f.c.ClaimDelivery(ctx, r.ID, signature, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("duplicate delivery", e)
	}
	return bundle, secret
}
func (f keyFixture) stage(t *testing.T, r ControlRequest) {
	t.Helper()
	bundle, secret := f.claim(t, r)
	defer clear(secret)
	if e := f.k.ConfirmPossession(context.Background(), r.ID, make([]byte, 32), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("invalid possession", e)
	}
	h := hmac.New(sha256.New, secret)
	h.Write(bundle.PossessionInput)
	if e := f.k.ConfirmPossession(context.Background(), r.ID, h.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
}
func (f keyFixture) operation(t *testing.T, kind string, version uint64, retireAt string) ControlRequest {
	t.Helper()
	ctx := context.Background()
	client, e := f.f.c.Client(ctx, f.f.tokens[0], "one")
	if e != nil {
		t.Fatal(e)
	}
	r, e := f.f.c.Submit(ctx, f.f.tokens[0], ControlOperation{Kind: kind, ClientID: "one", ExpectedRevision: client.Revision, KeyVersion: version, RetireAt: retireAt}, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	approveControl(t, f.f, r)
	if e = f.f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestSoftwareKeyLifecycle(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	k, e := f.f.c.Key(ctx, f.f.tokens[0], "one", 1)
	if e != nil || k.State != "pending" {
		t.Fatal(k, e)
	}
	client, e := f.f.c.Client(ctx, f.f.tokens[0], "one")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.f.c.Submit(ctx, f.f.tokens[0], ControlOperation{Kind: ActivateKey, ClientID: "one", ExpectedRevision: client.Revision, KeyVersion: 1}, unique(t), unique(t)); e == nil {
		t.Fatal("undelivered key activated")
	}
	if _, e = f.f.c.ClaimDelivery(ctx, r.ID, make([]byte, ed25519.SignatureSize), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("wrong recipient signed", e)
	}
	f.stage(t, r)
	f.operation(t, ActivateKey, 1, "")
	k, e = f.f.c.Key(ctx, f.f.tokens[0], "one", 1)
	if e != nil || k.State != "active" {
		t.Fatal(k, e)
	}
	// 幂等完成不再次消耗包裹预算，也不产生第二份版本。
	var before, after int64
	_ = f.f.db.QueryRow(`SELECT used FROM keygate.root_budgets WHERE root_id=$1`, f.k.rootID).Scan(&before)
	if e = f.k.ExecuteIssue(ctx, r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	_ = f.f.db.QueryRow(`SELECT used FROM keygate.root_budgets WHERE root_id=$1`, f.k.rootID).Scan(&after)
	if before != after || before != 1 {
		t.Fatal("completed issue consumed budget")
	}
	f.operation(t, DisableKey, 1, "")
	k, e = f.f.c.Key(ctx, f.f.tokens[0], "one", 1)
	if e != nil || k.State != "disabled" {
		t.Fatal(k, e)
	}
	if e = f.k.ConfirmPossession(ctx, r.ID, make([]byte, 32), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("disabled key restored", e)
	}
}
func TestSoftwareKeyRotationAndRecipientBinding(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	first := f.issue(t, 1)
	f.stage(t, first)
	f.operation(t, ActivateKey, 1, "")
	second := f.issue(t, 2)
	bundle, secret := f.claim(t, second)
	defer clear(secret)
	if _, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.recipient, bundle.Ciphertext, []byte("another-target")); e == nil {
		t.Fatal("unbound delivery ciphertext")
	}
	h := hmac.New(sha256.New, secret)
	h.Write(bundle.PossessionInput)
	if e := f.k.ConfirmPossession(ctx, second.ID, h.Sum(nil), unique(t)); e != nil {
		t.Fatal(e)
	}
	f.operation(t, ActivateKey, 2, time.Now().Add(5*time.Minute).UTC().Format("2006-01-02T15:04:05.000Z"))
	old, e := f.f.c.Key(ctx, f.f.tokens[0], "one", 1)
	if e != nil || old.State != "retiring" {
		t.Fatal(old, e)
	}
	active, e := f.f.c.Key(ctx, f.f.tokens[0], "one", 2)
	if e != nil || active.State != "active" {
		t.Fatal(active, e)
	}
}
func TestSoftwareKeyQuotaConcurrencyAndEmergency(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	client, _ := f.f.c.Client(ctx, f.f.tokens[0], "one")
	r, e := f.f.c.Submit(ctx, f.f.tokens[0], ControlOperation{Kind: IssueKey, ClientID: "one", ExpectedRevision: client.Revision, KeyVersion: 1, RootID: f.k.rootID, RecipientPublicKey: f.encoded, RecipientFingerprint: f.fingerprint, RecipientSigningKey: f.signingKey, RecipientSigningFingerprint: f.signingFingerprint, NotAfter: time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")}, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	approveControl(t, f.f, r)
	// 将软件预计算挡在独立预算锁上，在此期间提交应急停用，验证最终写回不会恢复已停用目标。
	blocker, e := f.f.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Rollback()
	if _, e = blocker.Exec(`SELECT root_id FROM keygate.root_budgets WHERE root_id=$1 FOR UPDATE`, f.k.rootID); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { result <- f.k.ExecuteIssue(ctx, r.ID, r.Digest, unique(t)) }()
	deadline := time.Now().Add(3 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		if e = f.f.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'UPDATE keygate.root_budgets%')`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("issue did not reach budget lock")
	}
	if e = f.f.c.EmergencyDisableClient(ctx, f.f.tokens[0], "one", unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = blocker.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = <-result; e == nil {
		t.Fatal("late result overwrote disabled client")
	}
	var count int
	if e = f.f.db.QueryRow(`SELECT count(*) FROM keygate.key_versions WHERE environment=$1`, f.f.c.environment).Scan(&count); e != nil || count != 0 {
		t.Fatal("discarded result persisted", e)
	}
	var used int64
	_ = f.f.db.QueryRow(`SELECT used FROM keygate.root_budgets WHERE root_id=$1`, f.k.rootID).Scan(&used)
	if used != 1 {
		t.Fatal("discarded crypto budget refunded")
	}
}
func TestConcurrentDeliverySingleClaim(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	challenge, e := f.f.c.DeliveryChallenge(ctx, r.ID)
	if e != nil {
		t.Fatal(e)
	}
	sig := ed25519.Sign(f.signer, challenge)
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := f.f.c.ClaimDelivery(ctx, r.ID, sig, unique(t)); e == nil {
				accepted.Add(1)
			} else if !errors.Is(e, ErrDenied) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("multiple deliveries", accepted.Load())
	}
}

func TestSoftwareKeyRootAndScopeGuards(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	r := f.issue(t, 1)
	if _, e := f.f.c.Key(ctx, f.f.tokens[5], "one", 1); !errors.Is(e, ErrDenied) {
		t.Fatal("ungranted secret metadata", e)
	}
	replacement, _ := keycrypto.Generate()
	defer clear(replacement)
	wrong, e := NewDevelopmentKeys(f.f.c, f.k.rootID, replacement, "login-root")
	if e != nil {
		t.Fatal(e)
	}
	bundle, secret := f.claim(t, r)
	defer clear(secret)
	h := hmac.New(sha256.New, secret)
	h.Write(bundle.PossessionInput)
	if e = wrong.ConfirmPossession(ctx, r.ID, h.Sum(nil), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("same root ID changed material", e)
	}
	if _, e = f.f.db.Exec(`UPDATE keygate.key_versions SET claim_expires=clock_timestamp()-interval '1 second' WHERE environment=$1 AND issue_id=$2`, f.f.c.environment, r.ID); e != nil {
		t.Fatal(e)
	}
	if e = f.k.ConfirmPossession(ctx, r.ID, h.Sum(nil), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("expired enrollment accepted", e)
	}
}
