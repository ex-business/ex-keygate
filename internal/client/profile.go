// Package client validates server-managed authentication profiles.
// A profile describes requirements; it does not authenticate a client.
package client

import (
	"errors"
	"regexp"
)

type Type string

const (
	Backend Type = "backend"
	Desktop Type = "desktop"
	Mobile  Type = "mobile"
	Browser Type = "browser"
)

type Method string

const (
	HMAC             Method = "hmac_sha256"
	MTLS             Method = "mtls"
	DeviceProof      Method = "device_proof"
	FederatedSession Method = "federated_session"
)

type Storage string

const (
	NoSecret    Storage = "none"
	ServerVault Storage = "server_vault"
	OSKeystore  Storage = "os_keystore"
	Hardware    Storage = "hardware"
)

var ErrInvalidProfile = errors.New("invalid authentication profile")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Profile struct {
	ID         string  `json:"id"`
	Version    uint64  `json:"version"`
	ClientType Type    `json:"clientType"`
	Method     Method  `json:"method"`
	Storage    Storage `json:"storage"`
	ProviderID string  `json:"providerId"`
}

// Validate rejects unknown types and unsafe combinations instead of selecting a
// fallback. Only a privileged management flow may bind a profile to a client.
func (p Profile) Validate() error {
	if !identifier.MatchString(p.ID) || !identifier.MatchString(p.ProviderID) || p.Version == 0 {
		return ErrInvalidProfile
	}
	switch p.ClientType {
	case Backend, Desktop, Mobile, Browser:
	default:
		return ErrInvalidProfile
	}
	switch p.Storage {
	case NoSecret, ServerVault, OSKeystore, Hardware:
	default:
		return ErrInvalidProfile
	}
	switch p.Method {
	case HMAC:
		// Public browser code cannot protect a long-lived shared secret.
		if p.ClientType == Browser {
			return ErrInvalidProfile
		}
		if p.ClientType == Backend && p.Storage != ServerVault && p.Storage != Hardware {
			return ErrInvalidProfile
		}
		if (p.ClientType == Desktop || p.ClientType == Mobile) && p.Storage != OSKeystore && p.Storage != Hardware {
			return ErrInvalidProfile
		}
	case MTLS:
		if p.ClientType == Browser || p.Storage == NoSecret {
			return ErrInvalidProfile
		}
		if p.ClientType == Backend && p.Storage == OSKeystore {
			return ErrInvalidProfile
		}
		if p.ClientType != Backend && p.Storage == ServerVault {
			return ErrInvalidProfile
		}
	case DeviceProof:
		if p.Storage != Hardware {
			return ErrInvalidProfile
		}
	case FederatedSession:
		if p.ClientType == Backend || p.Storage != NoSecret {
			return ErrInvalidProfile
		}
	default:
		return ErrInvalidProfile
	}
	return nil
}
