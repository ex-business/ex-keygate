package trustchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	now                            time.Time
	root                           []byte
	rootKey, statusKey, serviceKey ed25519.PrivateKey
	statusCert, cert               []byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{now: time.Now().UTC().Truncate(time.Second)}
	var e error
	f.root, f.rootKey, e = NewRoot("test-root", f.now)
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f.serviceKey = key
	f.cert, e = Issue(f.root, f.rootKey, pub, "test", ServicePurpose, "server", 1, f.now, f.now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ = ed25519.GenerateKey(rand.Reader)
	f.statusKey = key
	f.statusCert, e = Issue(f.root, f.rootKey, pub, "test", StatusPurpose, "trust-status", 1, f.now, f.now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f fixture) proof(t *testing.T, nonce string, version, revision uint64, cert []byte, key ed25519.PrivateKey) (Message, Status) {
	t.Helper()
	m, e := SignMessage(f.root, cert, key, "test", "server", version, "app", nonce, []byte("payload"), f.now)
	if e != nil {
		t.Fatal(e)
	}
	s, e := SignStatus(f.root, f.statusCert, f.statusKey, Status{Environment: "test", ServiceID: "server", Revision: revision, Version: version, CertificateHash: Fingerprint(cert), Nonce: nonce, Audience: "app"}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return m, s
}
func TestTrustVerificationAndFailures(t *testing.T) {
	f := newFixture(t)
	nonce, _ := NewNonce()
	m, s := f.proof(t, nonce, 1, 1, f.cert, f.serviceKey)
	v := Verifier{f.root, "test", "server", "app", &MemoryState{}}
	if e := v.Verify(m, s, nonce, []byte("payload"), f.now); e != nil {
		t.Fatal(e)
	}
	if e := v.Verify(m, s, nonce, []byte("payload"), f.now); e == nil {
		t.Fatal("接受重放")
	}
	cases := []struct {
		name   string
		mutate func(*Message, *Status)
	}{
		{"正文", func(m *Message, s *Status) { m.PayloadHash = Fingerprint([]byte("other")) }},
		{"环境", func(m *Message, s *Status) { m.Environment = "other" }},
		{"用途", func(m *Message, s *Status) { m.Audience = "other" }},
		{"旧版本", func(m *Message, s *Status) { s.Version = 2 }},
		{"撤销", func(m *Message, s *Status) {
			s.Disabled = true
			s.Signature = ed25519.Sign(f.statusKey, statusBytes(*s))
		}},
		{"状态替换", func(m *Message, s *Status) {
			s.CertificateHash = Fingerprint(f.statusCert)
			s.Signature = ed25519.Sign(f.statusKey, statusBytes(*s))
		}},
		{"旧状态挑战", func(m *Message, s *Status) {
			s.Nonce, _ = NewNonce()
			s.Signature = ed25519.Sign(f.statusKey, statusBytes(*s))
		}},
		{"业务签名伪造状态", func(m *Message, s *Status) {
			s.StatusCertificate = f.cert
			s.Signature = ed25519.Sign(f.serviceKey, statusBytes(*s))
		}},
		{"状态证书伪造业务", func(m *Message, s *Status) {
			m.Certificate = f.statusCert
			m.Signature = ed25519.Sign(f.statusKey, messageBytes(*m))
			s.CertificateHash = Fingerprint(m.Certificate)
			s.Signature = ed25519.Sign(f.statusKey, statusBytes(*s))
		}},
		{"时效", func(m *Message, s *Status) {
			s.ExpiresAt = s.IssuedAt + 31
			s.Signature = ed25519.Sign(f.statusKey, statusBytes(*s))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cm, cs := m, s
			tc.mutate(&cm, &cs)
			v.State = &MemoryState{}
			if v.Verify(cm, cs, nonce, []byte("payload"), f.now) == nil {
				t.Fatal("错误证明被放行")
			}
		})
	}
	v.State = &MemoryState{}
	if v.Verify(m, s, nonce, []byte("payload"), f.now.Add(30*time.Second)) == nil {
		t.Fatal("过期状态被接受")
	}
	if v.Verify(m, s, nonce, []byte("different"), f.now) == nil {
		t.Fatal("正文替换被接受")
	}
}
func TestRotationConcurrentReplayAndRollback(t *testing.T) {
	f := newFixture(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, e := Issue(f.root, f.rootKey, pub, "test", ServicePurpose, "server", 2, f.now, f.now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	n, _ := NewNonce()
	m, s := f.proof(t, n, 2, 3, cert, key)
	v := Verifier{f.root, "test", "server", "app", &MemoryState{}}
	var count atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v.Verify(m, s, n, []byte("payload"), f.now) == nil {
				count.Add(1)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal("并发挑战重复接受", count.Load())
	}
	n, _ = NewNonce()
	old, oldStatus := f.proof(t, n, 1, 1, f.cert, f.serviceKey)
	if v.Verify(old, oldStatus, n, []byte("payload"), f.now) == nil {
		t.Fatal("旧状态回退被接受")
	}
	other, _, _ := NewRoot("other", f.now)
	v.Root = other
	if v.Verify(m, s, n, []byte("payload"), f.now) == nil {
		t.Fatal("跨根被接受")
	}
}
func TestDurableChallengeRecoveryAndFailClosed(t *testing.T) {
	f := newFixture(t)
	recoveryPub, recoveryKey, _ := ed25519.GenerateKey(rand.Reader)
	pins := Pins{f.root, recoveryPub, 1, "test", "server", "app"}
	dir := filepath.Join(t.TempDir(), "client")
	if e := InitializeClient(dir, pins, f.now); e != nil {
		t.Fatal(e)
	}
	state, e := OpenClient(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = OpenClient(dir); e == nil {
		t.Fatal("文件锁未隔离")
	}
	nonce, e := state.Challenge(f.now)
	if e != nil {
		t.Fatal(e)
	}
	state.Close()
	state, e = OpenClient(dir)
	if e != nil {
		t.Fatal(e)
	}
	m, s := f.proof(t, nonce, 1, 2, f.cert, f.serviceKey)
	if e = state.Verify(m, s, nonce, []byte("payload"), f.now); e != nil {
		t.Fatal(e)
	}
	state.Close()
	state, e = OpenClient(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	if state.Verify(m, s, nonce, []byte("payload"), f.now) == nil {
		t.Fatal("重启后重放")
	}
	if _, e = state.Challenge(f.now.Add(-time.Second)); e == nil {
		t.Fatal("时钟回退被接受")
	}
	newRoot, _, _ := NewRoot("new-root", f.now)
	u, e := SignRecovery(pins, newRoot, recoveryKey, f.now)
	if e != nil {
		t.Fatal(e)
	}
	forged := u
	forged.Signature = ed25519.Sign(f.rootKey, recoveryBytes(forged))
	if state.Recover(forged, f.now) == nil {
		t.Fatal("旧根自授权恢复")
	}
	if e = state.Recover(u, f.now); e != nil {
		t.Fatal(e)
	}
	if state.Recover(u, f.now) == nil {
		t.Fatal("恢复代次回退")
	}
	if state.Pins.Epoch != 2 || state.Revision != 0 {
		t.Fatal("恢复状态不一致")
	}
	state.Close()
	if e = os.Remove(filepath.Join(dir, "state.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenClient(dir); e == nil {
		t.Fatal("状态缺失自动重建")
	}
}
func TestStrictCertificateAndJSON(t *testing.T) {
	f := newFixture(t)
	if _, e := VerifyCertificate(f.root, f.cert, "other", ServicePurpose, "server", 1, f.now); e == nil {
		t.Fatal("环境串用")
	}
	if _, e := VerifyCertificate(f.root, f.cert, "test", ServicePurpose, "server", 2, f.now); e == nil {
		t.Fatal("版本串用")
	}
	var value struct {
		A string `json:"a"`
	}
	for _, raw := range []string{`{"a":"x","a":"y"}`, `{"a":"x","b":1}`, `{"a":"x"} {}`} {
		if DecodeJSON([]byte(raw), &value) == nil {
			t.Fatal("非规范JSON被接受")
		}
	}
	b, _ := json.Marshal(value)
	if DecodeJSON(b, &value) != nil {
		t.Fatal("合法JSON被拒绝")
	}
}

func TestLargeClientStateCanReopen(t *testing.T) {
	f := newFixture(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := filepath.Join(t.TempDir(), "client")
	if e := InitializeClient(dir, Pins{f.root, pub, 1, "test", "server", "app"}, f.now); e != nil {
		t.Fatal(e)
	}
	s, e := OpenClient(dir)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3000; i++ {
		n, _ := NewNonce()
		s.Challenges[n] = f.now.Unix() + 60
	}
	if e = s.save(); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = OpenClient(dir)
	if e != nil {
		t.Fatal("合法容量状态无法重开", e)
	}
	defer s.Close()
	if len(s.Challenges) != 3000 {
		t.Fatal("状态丢失")
	}
}
