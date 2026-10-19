package access

import (
	"ex-keygate/internal/client"
	"ex-keygate/internal/identity"
	"testing"
)

func TestIdentityAndProfiles(t *testing.T) {
	a, e := NewPrincipal("https://issuer.example", "alice", "person-a")
	if e != nil {
		t.Fatal(e)
	}
	if a.ID != identity.PrincipalID("https://issuer.example", "alice") {
		t.Fatal("OIDC ID mismatch")
	}
	b, _ := NewPrincipal("https://other.example", "alice", "person-a")
	if a.ID == b.ID {
		t.Fatal("issuer collision")
	}
	c, _ := NewPrincipal("https://issuer.example", "alice-alias", "person-a")
	if a.ID == c.ID || a.PersonID != c.PersonID {
		t.Fatal("identity/person separation")
	}
	p := client.Profile{ID: "backend", Version: 1, ClientType: client.Backend, Method: client.HMAC, Storage: client.ServerVault, ProviderID: "internal-software"}
	if ValidateProfileV1(p) != nil {
		t.Fatal("backend rejected")
	}
	p.ClientType = client.Mobile
	p.Storage = client.OSKeystore
	if ValidateProfileV1(p) == nil {
		t.Fatal("native shared secret enabled")
	}
	p.Method = client.DeviceProof
	p.Storage = client.Hardware
	if ValidateProfileV1(p) == nil {
		t.Fatal("reserved hardware enabled")
	}
	if (Grant{PrincipalID: a.ID, Role: Role("executor_service")}).Validate() == nil {
		t.Fatal("human executor role")
	}
}
