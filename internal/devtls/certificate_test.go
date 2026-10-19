package devtls

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestEphemeralLoopbackTrust(t *testing.T) {
	cert, ca, err := Certificate("test")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid CA")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"127.0.0.1", "localhost"} {
		if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "remote.example"}); err == nil {
		t.Fatal("remote identity allowed")
	}
	block, rest := pem.Decode(ca)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("CA output contains unexpected material")
	}
	other, _, err := Certificate("other")
	if err != nil {
		t.Fatal(err)
	}
	if string(cert.Certificate[0]) == string(other.Certificate[0]) {
		t.Fatal("certificate reused")
	}
}
