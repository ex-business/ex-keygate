package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

// Binding 将实现模式和公开配置摘要冻结到审批对象，不包含 URL、私钥路径或材料。
type Binding struct {
	Schema            string     `json:"schema"`
	Descriptor        Descriptor `json:"descriptor"`
	Executor          string     `json:"executor"`
	ConfigurationHash string     `json:"configurationHash"`
}

func Hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func (b Binding) Validate() error {
	if b.Schema != "keygate-plugin-binding-v1" || b.Descriptor.Validate() != nil || len(b.ConfigurationHash) != 64 {
		return ErrInvalid
	}
	raw, e := hex.DecodeString(b.ConfigurationHash)
	if e != nil || hex.EncodeToString(raw) != b.ConfigurationHash {
		return ErrInvalid
	}
	switch b.Executor {
	case "internal_software":
		if b.Descriptor.ID != "internal-software" || b.Descriptor.Kind != Local || !slices.Equal(b.Descriptor.Capabilities, []Capability{Verify, Create, Rotate, Disable}) {
			return ErrInvalid
		}
	case "https_mtls":
		if b.Descriptor.Kind != ThirdParty || !slices.Equal(b.Descriptor.Capabilities, []Capability{Verify}) {
			return ErrInvalid
		}
	case "reserved":
	default:
		return ErrInvalid
	}
	return nil
}
func (b Binding) Encode() ([]byte, string, error) {
	if e := b.Validate(); e != nil {
		return nil, "", e
	}
	raw, e := json.Marshal(b)
	if e != nil {
		return nil, "", e
	}
	return raw, Hash(raw), nil
}
func InternalBinding() Binding {
	return Binding{Schema: "keygate-plugin-binding-v1", Descriptor: Descriptor{ID: "internal-software", Version: "1", ProtocolVersion: ProtocolVersion, Kind: Local, Capabilities: []Capability{Verify, Create, Rotate, Disable}}, Executor: "internal_software", ConfigurationHash: Hash([]byte("ex-keygate-internal-software-v1"))}
}
func HardwareBinding() Binding {
	return Binding{Schema: "keygate-plugin-binding-v1", Descriptor: Descriptor{ID: "hardware-reserved", Version: "1", ProtocolVersion: ProtocolVersion, Kind: Hardware, Capabilities: []Capability{DeviceInfo, Challenge}}, Executor: "reserved", ConfigurationHash: Hash([]byte("ex-keygate-hardware-reserved-v1"))}
}
