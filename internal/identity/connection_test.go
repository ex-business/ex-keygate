package identity

import (
	"encoding/json"
	"testing"
)

func TestConnectionMetadata(t *testing.T) {
	c := Connection{Issuer: "https://idp.example/realm", JWKSURL: "https://idp.example/keys", AuthorizationEndpoint: "https://idp.example/authorize", TokenEndpoint: "https://idp.example/token", ClientID: "keygate-admin", RedirectURI: "https://keygate.example/auth/callback", AllowedACR: []string{"urn:example:strong"}, RequiredAMR: []string{"pwd", "otp"}}
	raw, _ := json.Marshal(c)
	got, e := ParseConnection(raw)
	if e != nil || got.TokenAuthMethod != "none" || got.IdentityConfig().DevelopmentMode {
		t.Fatal("external metadata rejected", e)
	}
	for _, change := range []func(*Connection){
		func(c *Connection) { c.AllowedACR = []string{"urn:keygate:dev:simulated-mfa"} },
		func(c *Connection) { c.RequiredAMR = []string{"mock"} },
		func(c *Connection) { c.RequiredAMR = []string{"pwd", "pwd"} },
		func(c *Connection) { c.Subjects = []string{"admin"} },
		func(c *Connection) { c.TokenEndpoint = "https://other.example/token" },
		func(c *Connection) { c.RedirectURI = "https://keygate.example/other" },
		func(c *Connection) { c.TokenAuthMethod = "auto" },
	} {
		copy := c
		change(&copy)
		encoded, _ := json.Marshal(copy)
		if _, e := ParseConnection(encoded); e == nil {
			t.Fatal("unsafe metadata accepted")
		}
	}
	if _, e := ParseConnection(append(raw, raw...)); e == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, e := ParseConnection([]byte(`{"clientSecret":"must-not-be-in-metadata"}`)); e == nil {
		t.Fatal("unknown secret accepted")
	}
}
