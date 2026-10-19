// Package keycrypto provides software key-protection primitives, not a key vault.
package keycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"regexp"
)

const Format = "aes256-gcm-random-v1"

var (
	ErrInvalid = errors.New("invalid key protection input")
	ErrOpen    = errors.New("key authentication failed")
)
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// Binding must come from trusted application state, not the ciphertext envelope.
// Including environment and client prevents moving encrypted keys across scopes.
type Binding struct {
	Environment string `json:"environment"`
	ClientID    string `json:"clientId"`
	KeyID       string `json:"keyId"`
	Version     uint64 `json:"version"`
	Purpose     string `json:"purpose"`
}

func (b Binding) valid() bool {
	return identifier.MatchString(b.Environment) && identifier.MatchString(b.ClientID) && identifier.MatchString(b.KeyID) && b.Version > 0 && identifier.MatchString(b.Purpose)
}

type Envelope struct {
	Format     string `json:"format"`
	RootID     string `json:"rootId"`
	Ciphertext []byte `json:"ciphertext"`
}

type Wrapper struct {
	rootID string
	aead   cipher.AEAD
}

// New requires an externally provisioned 256-bit wrapping key. RootID must name
// one immutable key version, never an alias silently reassigned to another key.
// There are no default keys and no automatic software fallback from hardware.
func New(rootID string, key []byte) (*Wrapper, error) {
	if !identifier.MatchString(rootID) || len(key) != 32 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, ErrInvalid
	}
	return &Wrapper{rootID, aead}, nil
}
func Generate() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
func (w *Wrapper) aad(b Binding) ([]byte, error) {
	if w == nil || w.aead == nil || !b.valid() {
		return nil, ErrInvalid
	}
	return json.Marshal(struct {
		Format  string  `json:"format"`
		RootID  string  `json:"rootId"`
		Binding Binding `json:"binding"`
	}{Format, w.rootID, b})
}

// Seal protects exactly one 256-bit client key. Before production use the caller
// must enforce a durable global wrapping-key usage budget across all nodes and
// restores, strictly below the standard library's 2^32-message limit per key.
func (w *Wrapper) Seal(b Binding, key []byte) (Envelope, error) {
	aad, err := w.aad(b)
	if err != nil || len(key) != 32 {
		return Envelope{}, ErrInvalid
	}
	return Envelope{Format, w.rootID, w.aead.Seal(nil, nil, key, aad)}, nil
}
func (w *Wrapper) Open(b Binding, envelope Envelope) ([]byte, error) {
	aad, err := w.aad(b)
	if err != nil || envelope.Format != Format || envelope.RootID != w.rootID {
		return nil, ErrOpen
	}
	// Fixed-size envelopes bound allocation and reject malformed inputs early.
	if len(envelope.Ciphertext) != 32+w.aead.Overhead() {
		return nil, ErrOpen
	}
	key, err := w.aead.Open(nil, nil, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return key, nil
}
