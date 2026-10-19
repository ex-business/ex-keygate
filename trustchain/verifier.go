package trustchain

import (
	"crypto/ed25519"
	"sync"
	"time"
)

// StateStore 的实现必须原子持久化水位和已消费nonce；丢失、回滚或不可用时拒绝验证。
// revision使用十进制单调水位，同一nonce无论业务版本如何都只允许消费一次。
type StateStore interface {
	Accept(environment, service, nonce string, revision uint64, expiresAt, now time.Time) error
}
type Verifier struct {
	Root                             []byte
	Environment, ServiceID, Audience string
	State                            StateStore
}

// Verify 同时核验证书链、业务签名、独立状态签名、挑战、用途、版本和时效，最后原子消费挑战。
// 客户端必须为每次验证生成全新nonce并向可信状态接口请求响应，不能用历史快照离线放行。
func (v Verifier) Verify(m Message, s Status, nonce string, payload []byte, now time.Time) error {
	if v.State == nil || !ValidNonce(nonce) || m.Schema != protocol || s.Schema != protocol || m.Environment != v.Environment || s.Environment != v.Environment || m.ServiceID != v.ServiceID || s.ServiceID != v.ServiceID || m.Audience != v.Audience || s.Audience != v.Audience || m.Nonce != nonce || s.Nonce != nonce || m.PayloadHash != Fingerprint(payload) || !timeWindow(m.IssuedAt, m.ExpiresAt, now, 60) || !timeWindow(s.IssuedAt, s.ExpiresAt, now, 30) || s.Disabled || s.Version != m.Version || s.CertificateHash != Fingerprint(m.Certificate) || (s.Revision == 0 || s.Revision > 9007199254740991 || s.Version > 9007199254740991) {
		return ErrInvalid
	}
	pub, e := VerifyCertificate(v.Root, m.Certificate, v.Environment, ServicePurpose, v.ServiceID, m.Version, now)
	if e != nil || !ed25519.Verify(pub, messageBytes(m), m.Signature) {
		return ErrInvalid
	}
	statusPub, e := VerifyCertificate(v.Root, s.StatusCertificate, v.Environment, StatusPurpose, "trust-status", 1, now)
	if e != nil || !ed25519.Verify(statusPub, statusBytes(s), s.Signature) {
		return ErrInvalid
	}
	expiry := time.Unix(m.ExpiresAt, 0)
	return v.State.Accept(v.Environment, v.ServiceID, nonce, s.Revision, expiry, now)
}

// MemoryState 仅用于进程内测试；跨重启的应用应提供可靠持久存储或使用CLI文件状态。
type MemoryState struct {
	mu        sync.Mutex
	revisions map[string]uint64
	nonces    map[string]time.Time
}

func (s *MemoryState) Accept(environment, service, nonce string, revision uint64, expiry, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revisions == nil {
		s.revisions = map[string]uint64{}
		s.nonces = map[string]time.Time{}
	}
	scope := environment + ":" + service
	if revision < s.revisions[scope] {
		return ErrInvalid
	}
	for n, e := range s.nonces {
		if !now.Before(e) {
			delete(s.nonces, n)
		}
	}
	key := scope + ":" + nonce
	if _, ok := s.nonces[key]; ok {
		return ErrInvalid
	}
	if len(s.nonces) >= 10000 {
		return ErrInvalid
	}
	s.revisions[scope] = revision
	s.nonces[key] = expiry
	return nil
}
