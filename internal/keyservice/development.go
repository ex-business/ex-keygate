// Package keyservice connects key protection to persistent usage accounting.
package keyservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"ex-keygate/internal/config"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/storage"
)

var ErrDevelopmentOnly = errors.New("software protector is restricted to development and test")

type Development struct {
	rootID  string
	wrapper *keycrypto.Wrapper
	store   *storage.Store
}

func NewDevelopment(environment config.Environment, rootID string, key []byte, store *storage.Store) (*Development, error) {
	if environment != config.Development && environment != config.Test {
		return nil, ErrDevelopmentOnly
	}
	if store == nil {
		return nil, storage.ErrInvalid
	}
	wrapper, err := keycrypto.New(rootID, key)
	if err != nil {
		return nil, err
	}
	return &Development{rootID, wrapper, store}, nil
}
func (p *Development) RootID() string { return p.rootID }

// Seal reserves against the exact immutable root used by this protector before
// encryption. The root must have been provisioned under the same global budget.
// Failed or uncertain attempts consume quota; retries cannot refund nonce uses.
func (p *Development) Seal(ctx context.Context, binding keycrypto.Binding, secret []byte, actor, requestID string) (keycrypto.Envelope, error) {
	var event [16]byte
	if _, err := rand.Read(event[:]); err != nil {
		return keycrypto.Envelope{}, err
	}
	err := p.store.ReserveWrappingUse(ctx, p.rootID, storage.Audit{EventID: "wrap-" + hex.EncodeToString(event[:]), RequestID: requestID, ActorID: actor, Action: "root_wrap_reserve", TargetID: p.rootID, Result: "reserved"})
	if err != nil {
		return keycrypto.Envelope{}, err
	}
	return p.wrapper.Seal(binding, secret)
}

// Open is a protection primitive, not a grant. Callers must authorize the target
// and establish the trusted binding before requesting plaintext.
func (p *Development) Open(ctx context.Context, binding keycrypto.Binding, envelope keycrypto.Envelope) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.wrapper.Open(binding, envelope)
}
