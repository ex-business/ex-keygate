package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"testing"
	"time"
)

func fixture(t *testing.T) (*OIDC, *ecdsa.PrivateKey, map[string]any, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	nonce := make([]byte, 32)
	rand.Read(nonce)
	n := base64.RawURLEncoding.EncodeToString(nonce)
	config := Config{Issuer: "https://identity.example", JWKSURL: "https://identity.example/keys", ClientID: "keygate-console", AllowedACR: []string{"urn:example:mfa"}, MaxAuthAge: 5 * time.Minute}
	if config.validate() != nil {
		t.Fatal("invalid test config")
	}
	v := newOIDC(config, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, func() time.Time { return now })
	claims := map[string]any{"iss": config.Issuer, "aud": config.ClientID, "sub": "operator-1", "iat": now.Unix(), "exp": now.Add(4 * time.Minute).Unix(), "auth_time": now.Add(-time.Minute).Unix(), "acr": "urn:example:mfa", "nonce": n}
	return v, key, claims, n
}
func sign(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func TestLoginIdentity(t *testing.T) {
	v, key, c, n := fixture(t)
	first, err := v.VerifyLogin(context.Background(), sign(t, key, c), n)
	if err != nil || first.ID == "" {
		t.Fatal(err)
	}
	c["email"] = "changed@example.invalid"
	second, err := v.VerifyLogin(context.Background(), sign(t, key, c), n)
	if err != nil || first.ID != second.ID {
		t.Fatal("email affected identity", err)
	}
	c["sub"] = "another"
	other, err := v.VerifyLogin(context.Background(), sign(t, key, c), n)
	if err != nil || first.ID == other.ID {
		t.Fatal("subjects merged", err)
	}
}
func TestDeniedLoginClaims(t *testing.T) {
	for _, field := range []string{"iss", "aud", "sub", "iat", "exp", "auth_time", "acr", "nonce"} {
		t.Run("missing-"+field, func(t *testing.T) {
			v, key, c, n := fixture(t)
			delete(c, field)
			if _, err := v.VerifyLogin(context.Background(), sign(t, key, c), n); !errors.Is(err, ErrIdentity) {
				t.Fatal("missing claim accepted", err)
			}
		})
	}
	cases := []struct {
		name   string
		change func(map[string]any, time.Time)
	}{
		{"issuer", func(c map[string]any, n time.Time) { c["iss"] = "https://other.example" }},
		{"audience", func(c map[string]any, n time.Time) { c["aud"] = "other" }},
		{"future-issued", func(c map[string]any, n time.Time) { c["iat"] = n.Add(time.Minute).Unix() }},
		{"expired", func(c map[string]any, n time.Time) { c["exp"] = n.Unix() }},
		{"long-lifetime", func(c map[string]any, n time.Time) { c["exp"] = n.Add(time.Hour).Unix() }},
		{"old-auth", func(c map[string]any, n time.Time) { c["auth_time"] = n.Add(-5 * time.Minute).Unix() }},
		{"future-auth", func(c map[string]any, n time.Time) { c["auth_time"] = n.Add(time.Minute).Unix() }},
		{"password-only", func(c map[string]any, n time.Time) { c["acr"] = "password" }},
		{"multi-audience", func(c map[string]any, n time.Time) { c["aud"] = []string{"keygate-console", "other"} }},
		{"wrong-azp", func(c map[string]any, n time.Time) { c["azp"] = "other" }},
		{"future-nbf", func(c map[string]any, n time.Time) { c["nbf"] = n.Add(time.Minute).Unix() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, key, c, n := fixture(t)
			tc.change(c, v.now())
			if _, err := v.VerifyLogin(context.Background(), sign(t, key, c), n); !errors.Is(err, ErrIdentity) {
				t.Fatal("bad claims accepted", err)
			}
		})
	}
}
func TestNonceSignatureAndConfig(t *testing.T) {
	v, key, c, n := fixture(t)
	raw := sign(t, key, c)
	if _, err := v.VerifyLogin(context.Background(), raw, n[:42]); !errors.Is(err, ErrIdentity) {
		t.Fatal(err)
	}
	c["nonce"] = "other"
	if _, err := v.VerifyLogin(context.Background(), sign(t, key, c), n); !errors.Is(err, ErrIdentity) {
		t.Fatal(err)
	}
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c["nonce"] = n
	if _, err := v.VerifyLogin(context.Background(), sign(t, wrong, c), n); !errors.Is(err, ErrIdentity) {
		t.Fatal("wrong signature accepted")
	}
	configs := []Config{v.config, v.config, v.config, v.config}
	configs[0].Issuer = "http://identity.example"
	configs[1].JWKSURL = "https://untrusted.example/keys"
	configs[2].AllowedACR = nil
	configs[3].MaxAuthAge = time.Hour
	for _, config := range configs {
		if _, err := NewOIDC(config); !errors.Is(err, ErrConfig) {
			t.Fatal("unsafe config accepted", err)
		}
	}
}

func TestRejectUnsignedAndSharedSecretAlgorithms(t *testing.T) {
	v, _, claims, nonce := fixture(t)
	payload, _ := json.Marshal(claims)
	for _, algorithm := range []string{"none", "HS256"} {
		header, _ := json.Marshal(map[string]string{"alg": algorithm})
		token := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
		if _, err := v.VerifyLogin(context.Background(), token, nonce); !errors.Is(err, ErrIdentity) {
			t.Fatal("unsafe algorithm accepted", algorithm)
		}
	}
}
