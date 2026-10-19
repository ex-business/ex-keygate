package trustchain

import (
	"crypto/ed25519"
	"ex-keygate/internal/manifest"
	"time"
)

type Pins struct {
	Root              []byte `json:"root"`
	RecoveryPublicKey []byte `json:"recoveryPublicKey"`
	Epoch             uint64 `json:"epoch"`
	Environment       string `json:"environment"`
	ServiceID         string `json:"serviceId"`
	Audience          string `json:"audience"`
}
type RecoveryUpdate struct {
	Schema       string `json:"schema"`
	Environment  string `json:"environment"`
	PreviousRoot string `json:"previousRoot"`
	Epoch        uint64 `json:"epoch"`
	NewRoot      []byte `json:"newRoot"`
	IssuedAt     int64  `json:"issuedAt"`
	ExpiresAt    int64  `json:"expiresAt"`
	Signature    []byte `json:"signature,omitempty"`
}

func recoveryBytes(u RecoveryUpdate) []byte {
	u.Signature = nil
	b, _ := manifest.Canonical(u)
	return append([]byte(protocol+"/root-recovery\x00"), b...)
}

// SignRecovery 必须持有与日常根私钥独立的恢复私钥；旧根私钥不能授权自身替代。
func SignRecovery(p Pins, newRoot []byte, recovery ed25519.PrivateKey, now time.Time) (RecoveryUpdate, error) {
	if len(recovery) != ed25519.PrivateKeySize || len(p.RecoveryPublicKey) != ed25519.PublicKeySize || !ed25519.PublicKey(p.RecoveryPublicKey).Equal(recovery.Public()) || p.Epoch == 0 || p.Epoch >= 9007199254740991 || Fingerprint(newRoot) == Fingerprint(p.Root) {
		return RecoveryUpdate{}, ErrInvalid
	}
	if _, e := ParseRoot(newRoot, now); e != nil {
		return RecoveryUpdate{}, e
	}
	u := RecoveryUpdate{Schema: protocol, Environment: p.Environment, PreviousRoot: Fingerprint(p.Root), Epoch: p.Epoch + 1, NewRoot: newRoot, IssuedAt: now.Unix(), ExpiresAt: now.Add(24 * time.Hour).Unix()}
	u.Signature = ed25519.Sign(recovery, recoveryBytes(u))
	return u, nil
}

// ApplyRecovery 只认预置恢复公钥及严格递增代次；调用者须原子持久化新Pins和新水位再允许验证。
// 分发更新仍依赖可信运维或应用更新通道，不能依靠已失陷旧根证明更新正确。
func ApplyRecovery(p Pins, u RecoveryUpdate, now time.Time) (Pins, error) {
	if len(p.RecoveryPublicKey) != ed25519.PublicKeySize || u.Schema != protocol || u.Environment != p.Environment || u.PreviousRoot != Fingerprint(p.Root) || p.Epoch == 0 || u.Epoch != p.Epoch+1 || u.Epoch > 9007199254740991 || !timeWindow(u.IssuedAt, u.ExpiresAt, now, 86400) || !ed25519.Verify(ed25519.PublicKey(p.RecoveryPublicKey), recoveryBytes(u), u.Signature) {
		return Pins{}, ErrInvalid
	}
	if _, e := ParseRoot(u.NewRoot, now); e != nil {
		return Pins{}, e
	}
	if Fingerprint(u.NewRoot) == Fingerprint(p.Root) {
		return Pins{}, ErrInvalid
	}
	p.Root = append([]byte(nil), u.NewRoot...)
	p.Epoch = u.Epoch
	return p, nil
}
