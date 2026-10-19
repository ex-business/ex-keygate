// Package trustchain 实现应用内固定根证书的业务签名验证；与HTTPS及存储加密根隔离。
package trustchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"time"
)

var ErrInvalid = errors.New("信任链或签名验证失败")
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

const ServicePurpose = "service-signing"
const StatusPurpose = "status-signing"

func Fingerprint(der []byte) string { sum := sha256.Sum256(der); return hex.EncodeToString(sum[:]) }
func ValidID(id string) bool        { return idPattern.MatchString(id) }
func serial() (*big.Int, error) {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	if n.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return n, nil
}

// NewRoot 仅由离线工具调用，固定Ed25519及零级下级CA，防止业务证书自行转授信任。
func NewRoot(name string, now time.Time) ([]byte, ed25519.PrivateKey, error) {
	if !ValidID(name) || now.IsZero() {
		return nil, nil, ErrInvalid
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	n, e := serial()
	if e != nil {
		return nil, nil, e
	}
	t := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SignatureAlgorithm: x509.PureEd25519}
	der, e := x509.CreateCertificate(rand.Reader, t, t, pub, key)
	return der, key, e
}
func ParseRoot(der []byte, now time.Time) (*x509.Certificate, error) {
	if len(der) > 16384 {
		return nil, ErrInvalid
	}
	c, e := x509.ParseCertificate(der)
	if e != nil || !c.IsCA || !c.BasicConstraintsValid || !c.MaxPathLenZero || c.MaxPathLen != 0 || c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || c.SignatureAlgorithm != x509.PureEd25519 || now.Before(c.NotBefore) || !now.Before(c.NotAfter) || c.CheckSignatureFrom(c) != nil {
		return nil, ErrInvalid
	}
	if _, ok := c.PublicKey.(ed25519.PublicKey); !ok {
		return nil, ErrInvalid
	}
	return c, nil
}
func bindingURI(environment, purpose, service string, version uint64) *url.URL {
	return &url.URL{Scheme: "keygate", Opaque: fmt.Sprintf("%s:%s:%s:%d", environment, purpose, service, version)}
}

// Issue 根私钥只在离线签发期间使用；用途、环境、服务和版本全部进入签名证书。
func Issue(rootDER []byte, rootKey ed25519.PrivateKey, public ed25519.PublicKey, environment, purpose, service string, version uint64, now, notAfter time.Time) ([]byte, error) {
	root, e := ParseRoot(rootDER, now)
	if e != nil || len(rootKey) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize || !root.PublicKey.(ed25519.PublicKey).Equal(rootKey.Public()) || !ValidID(environment) || !ValidID(service) || version == 0 || version > 9007199254740991 || (purpose != ServicePurpose && purpose != StatusPurpose) || !notAfter.After(now) || notAfter.After(now.Add(24*time.Hour)) || notAfter.After(root.NotAfter) {
		return nil, ErrInvalid
	}
	n, e := serial()
	if e != nil {
		return nil, e
	}
	t := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: service}, NotBefore: now.Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: []*url.URL{bindingURI(environment, purpose, service, version)}, SignatureAlgorithm: x509.PureEd25519}
	return x509.CreateCertificate(rand.Reader, t, root, public, rootKey)
}

// VerifyCertificate 仅信任调用者固定的应用根，不读取系统证书库，不联网获取未知CA。
func VerifyCertificate(rootDER, leafDER []byte, environment, purpose, service string, version uint64, now time.Time) (ed25519.PublicKey, error) {
	root, e := ParseRoot(rootDER, now)
	if e != nil || len(leafDER) > 16384 || !ValidID(environment) || !ValidID(service) || version == 0 {
		return nil, ErrInvalid
	}
	leaf, e := x509.ParseCertificate(leafDER)
	if e != nil || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature || leaf.SignatureAlgorithm != x509.PureEd25519 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != bindingURI(environment, purpose, service, version).String() || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) > 0 || leaf.NotAfter.Sub(leaf.NotBefore) > 24*time.Hour+time.Minute {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return nil, ErrInvalid
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalid
	}
	return pub, nil
}
