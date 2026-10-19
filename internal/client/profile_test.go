package client

import "testing"

func TestProfiles(t *testing.T) {
	cases := []struct {
		typ     Type
		method  Method
		storage Storage
		valid   bool
	}{
		{Backend, HMAC, ServerVault, true}, {Desktop, HMAC, OSKeystore, true}, {Mobile, HMAC, Hardware, true},
		{Browser, HMAC, Hardware, false}, {Browser, FederatedSession, NoSecret, true}, {Browser, DeviceProof, Hardware, true},
		{Backend, HMAC, NoSecret, false}, {Mobile, HMAC, ServerVault, false}, {Desktop, MTLS, OSKeystore, true},
		{Backend, FederatedSession, NoSecret, false}, {Browser, MTLS, OSKeystore, false}, {"unknown", HMAC, Hardware, false},
		{Mobile, "unknown", Hardware, false}, {Desktop, HMAC, "unknown", false},
	}
	for _, c := range cases {
		t.Run(string(c.typ)+"/"+string(c.method)+"/"+string(c.storage), func(t *testing.T) {
			p := Profile{"profile", 1, c.typ, c.method, c.storage, "local"}
			if got := p.Validate() == nil; got != c.valid {
				t.Fatalf("valid=%v expected=%v", got, c.valid)
			}
		})
	}
}
func TestProfileIdentity(t *testing.T) {
	p := Profile{"profile", 1, Backend, HMAC, ServerVault, "local"}
	p.Version = 0
	if p.Validate() == nil {
		t.Fatal("zero version accepted")
	}
	p.Version = 1
	p.ProviderID = "https://attacker.invalid"
	if p.Validate() == nil {
		t.Fatal("URL accepted as provider ID")
	}
}
