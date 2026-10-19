// Package provider defines versioned, transport-independent provider contracts.
// Providers never decide whether management approval is sufficient.
package provider

import (
	"context"
	"errors"
	"regexp"
	"slices"
)

const ProtocolVersion = "1"

type Kind string

const (
	Local      Kind = "local"
	ThirdParty Kind = "third_party"
	Hardware   Kind = "hardware"
)

type Capability string

const (
	Verify     Capability = "verify"
	Create     Capability = "create"
	Rotate     Capability = "rotate"
	Disable    Capability = "disable"
	DeviceInfo Capability = "device_info"
	Challenge  Capability = "challenge"
)

var (
	ErrUnsupported    = errors.New("provider capability unsupported")
	ErrUnavailable    = errors.New("provider unavailable")
	ErrInvalid        = errors.New("invalid provider descriptor")
	ErrUnknownOutcome = errors.New("provider operation outcome unknown")
)
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Descriptor struct {
	ID              string       `json:"id"`
	Version         string       `json:"version"`
	ProtocolVersion string       `json:"protocolVersion"`
	Kind            Kind         `json:"kind"`
	Capabilities    []Capability `json:"capabilities"`
}

func (d Descriptor) Validate() error {
	if !identifier.MatchString(d.ID) || !identifier.MatchString(d.Version) || d.ProtocolVersion != ProtocolVersion {
		return ErrInvalid
	}
	switch d.Kind {
	case Local, ThirdParty, Hardware:
	default:
		return ErrInvalid
	}
	seen := map[Capability]bool{}
	for _, c := range d.Capabilities {
		switch c {
		case Verify, Create, Rotate, Disable, DeviceInfo, Challenge:
		default:
			return ErrInvalid
		}
		if seen[c] {
			return ErrInvalid
		}
		seen[c] = true
	}
	return nil
}

// Catalog snapshots reviewed manifests. Declaring a capability does not implement
// it: runtime wiring must also require the matching typed provider interface.
// No remote URL, device secret or key material belongs in a descriptor.
type Catalog struct{ entries map[string]Descriptor }

func NewCatalog(descriptors ...Descriptor) (*Catalog, error) {
	c := &Catalog{entries: make(map[string]Descriptor)}
	for _, d := range descriptors {
		if err := d.Validate(); err != nil {
			return nil, err
		}
		if _, ok := c.entries[d.ID]; ok {
			return nil, ErrInvalid
		}
		d.Capabilities = slices.Clone(d.Capabilities)
		c.entries[d.ID] = d
	}
	return c, nil
}
func (c *Catalog) Require(id string, capability Capability) (Descriptor, error) {
	if c == nil {
		return Descriptor{}, ErrUnavailable
	}
	d, ok := c.entries[id]
	if !ok || !slices.Contains(d.Capabilities, capability) {
		return Descriptor{}, ErrUnsupported
	}
	d.Capabilities = slices.Clone(d.Capabilities)
	return d, nil
}

type KeyReference struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}
type Verification struct {
	RequestID string
	ClientID  string
	Key       KeyReference
	Algorithm string
	// Payload must already bind the client, audience, purpose and replay fields.
	Payload []byte
	Proof   []byte
}
type Verifier interface {
	Verify(context.Context, Verification) error
}
type HealthChecker interface{ CheckHealth(context.Context) error }

// Hardware interfaces are reservations only. Device access, attestation trust and
// lifecycle authorization must be implemented and reviewed before registration.
type Device struct {
	Reference string `json:"reference"`
	Model     string `json:"model"`
	Ready     bool   `json:"ready"`
}
type DeviceInspector interface {
	Inspect(context.Context, string) (Device, error)
}
type HardwareChallenge struct {
	RequestID   string
	SubjectID   string
	Audience    string
	Purpose     string
	ChallengeID string
}
type ChallengeIssuer interface {
	Issue(context.Context, HardwareChallenge) ([]byte, error)
}
type ChallengeVerifier interface {
	VerifyChallenge(context.Context, HardwareChallenge, []byte) error
}
