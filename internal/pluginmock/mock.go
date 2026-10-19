// Package pluginmock 仅提供开发用第三方核验服务；公开自检向量不是客户端认证凭据。
package pluginmock

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"ex-keygate/provider"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"
)

const ID = "third-party-demo"

func Descriptor() provider.Descriptor {
	return provider.Descriptor{ID: ID, Version: "1", ProtocolVersion: provider.ProtocolVersion, Kind: provider.ThirdParty, Capabilities: []provider.Capability{provider.Verify}}
}

type Service struct {
	public         ed25519.PublicKey
	payload, proof []byte
}

func New() (*Service, error) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	payload := []byte("keygate-provider-conformance-v1")
	proof := ed25519.Sign(key, payload)
	clear(key)
	return &Service{pub, payload, proof}, nil
}
func (s *Service) Vector() ([]byte, []byte) {
	return append([]byte(nil), s.payload...), append([]byte(nil), s.proof...)
}
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			http.Error(w, "invalid", 400)
			return
		}
		ready := true
		write(w, provider.WireHealth{ProtocolVersion: provider.ProtocolVersion, ProviderID: ID, ProviderVersion: "1", Ready: &ready})
	})
	mux.HandleFunc("POST /v1/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "invalid", 400)
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 100000))
		if e != nil {
			http.Error(w, "invalid", 400)
			return
		}
		var in provider.WireVerification
		if provider.DecodeStrict(raw, &in) != nil || in.ProviderID != ID || in.ProviderVersion != "1" || in.ProtocolVersion != provider.ProtocolVersion {
			http.Error(w, "invalid", 400)
			return
		}
		verified := in.Algorithm == "ed25519" && in.Key.ID == "mock-conformance" && in.Key.Version == 1 && in.Purpose == "conformance" && len(in.Payload) <= 65536 && ed25519.Verify(s.public, in.Payload, in.Proof)
		digest := sha256.Sum256(raw)
		write(w, provider.WireResult{ProtocolVersion: provider.ProtocolVersion, ProviderID: ID, ProviderVersion: "1", RequestID: in.RequestID, RequestDigest: hex.EncodeToString(digest[:]), Verified: &verified})
	})
	return mux
}

// DevelopmentTLS 为模拟插件单独生成双向 TLS 身份，CA 私钥仅留内存，不复用管理登录或软件根。
func DevelopmentTLS() (tls.Certificate, []byte, []byte, []byte, error) {
	fail := func(e error) (tls.Certificate, []byte, []byte, []byte, error) {
		return tls.Certificate{}, nil, nil, nil, e
	}
	caPub, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return fail(e)
	}
	defer clear(caKey)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "ExKeyGate development plugin CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if e != nil {
		return fail(e)
	}
	leaf := func(client bool) ([]byte, []byte, error) {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		defer clear(key)
		serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if e != nil {
			return nil, nil, e
		}
		cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ExKeyGate development plugin"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			cert.DNSNames = []string{"localhost"}
		}
		der, e := x509.CreateCertificate(rand.Reader, cert, ca, pub, caKey)
		if e != nil {
			return nil, nil, e
		}
		keyDER, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return nil, nil, e
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
	}
	serverPEM, serverKey, e := leaf(false)
	if e != nil {
		return fail(e)
	}
	defer clear(serverKey)
	server, e := tls.X509KeyPair(serverPEM, serverKey)
	if e != nil {
		return fail(e)
	}
	clientPEM, clientKey, e := leaf(true)
	if e != nil {
		return fail(e)
	}
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), clientPEM, clientKey, nil
}
