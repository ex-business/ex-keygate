package trustchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"ex-keygate/internal/manifest"
	"time"
)

const protocol = "keygate-application-trust-v1"

func NewNonce() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func ValidNonce(n string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(n)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == n
}

type Message struct {
	Schema      string `json:"schema"`
	Environment string `json:"environment"`
	ServiceID   string `json:"serviceId"`
	Version     uint64 `json:"version"`
	Certificate []byte `json:"certificate"`
	Audience    string `json:"audience"`
	Nonce       string `json:"nonce"`
	PayloadHash string `json:"payloadHash"`
	IssuedAt    int64  `json:"issuedAt"`
	ExpiresAt   int64  `json:"expiresAt"`
	Signature   []byte `json:"signature,omitempty"`
}
type Status struct {
	Schema            string `json:"schema"`
	Environment       string `json:"environment"`
	ServiceID         string `json:"serviceId"`
	Revision          uint64 `json:"revision"`
	Version           uint64 `json:"version"`
	CertificateHash   string `json:"certificateHash"`
	Disabled          bool   `json:"disabled"`
	Nonce             string `json:"nonce"`
	Audience          string `json:"audience"`
	IssuedAt          int64  `json:"issuedAt"`
	ExpiresAt         int64  `json:"expiresAt"`
	StatusCertificate []byte `json:"statusCertificate"`
	Signature         []byte `json:"signature,omitempty"`
}

func messageBytes(m Message) []byte {
	m.Signature = nil
	b, _ := manifest.Canonical(m)
	return append([]byte(protocol+"/message\x00"), b...)
}
func statusBytes(s Status) []byte {
	s.Signature = nil
	b, _ := manifest.Canonical(s)
	return append([]byte(protocol+"/status\x00"), b...)
}
func timeWindow(issued, expires int64, now time.Time, max int64) bool {
	return issued > 0 && expires > issued && expires-issued <= max && issued <= now.Unix() && now.Unix() < expires
}

// SignMessage 接收客户端随机挑战，并把用途、目标与正文摘要绑定；不能把普通业务签名当状态签名使用。
func SignMessage(root, certificate []byte, key ed25519.PrivateKey, environment, service string, version uint64, audience, nonce string, payload []byte, now time.Time) (Message, error) {
	pub, e := VerifyCertificate(root, certificate, environment, ServicePurpose, service, version, now)
	if e != nil || len(key) != ed25519.PrivateKeySize || !pub.Equal(key.Public()) || !ValidID(audience) || !ValidNonce(nonce) {
		return Message{}, ErrInvalid
	}
	m := Message{Schema: protocol, Environment: environment, ServiceID: service, Version: version, Certificate: certificate, Audience: audience, Nonce: nonce, PayloadHash: Fingerprint(payload), IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 60}
	m.Signature = ed25519.Sign(key, messageBytes(m))
	return m, nil
}

// SignStatus 只能使用专用状态证书。状态响应绑定本次客户端挑战，不能重放旧的撤销前响应。
func SignStatus(root, certificate []byte, key ed25519.PrivateKey, s Status, now time.Time) (Status, error) {
	pub, e := VerifyCertificate(root, certificate, s.Environment, StatusPurpose, "trust-status", 1, now)
	if e != nil || len(key) != ed25519.PrivateKeySize || !pub.Equal(key.Public()) || !ValidID(s.ServiceID) || !ValidID(s.Audience) || !ValidNonce(s.Nonce) || (s.Revision == 0 || s.Revision > 9007199254740991 || s.Version > 9007199254740991) {
		return Status{}, ErrInvalid
	}
	s.Schema = protocol
	s.StatusCertificate = certificate
	s.IssuedAt = now.Unix()
	s.ExpiresAt = now.Unix() + 30
	s.Signature = ed25519.Sign(key, statusBytes(s))
	return s, nil
}

// PossessionProof 证明业务证书持有人控制对应私钥；证书指纹本身绑定环境、用途和版本。
func PossessionProof(certificate []byte, key ed25519.PrivateKey) []byte {
	if len(key) != ed25519.PrivateKeySize {
		return nil
	}
	return ed25519.Sign(key, []byte(protocol+"/possession\x00"+Fingerprint(certificate)))
}
func VerifyPossession(public ed25519.PublicKey, certificate, proof []byte) bool {
	return ed25519.Verify(public, []byte(protocol+"/possession\x00"+Fingerprint(certificate)), proof)
}
