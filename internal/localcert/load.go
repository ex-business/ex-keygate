// Package localcert 只加载本机开发用的固定证书，不安装信任根，也不降低TLS校验标准。
package localcert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var ErrCertificate = errors.New("本机开发证书无效或文件权限不安全")

func Load(directory string) (tls.Certificate, []byte, error) {
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return tls.Certificate{}, nil, ErrCertificate
	}
	certificate, e := read(filepath.Join(directory, "cert.pem"), false)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	key, e := read(filepath.Join(directory, "key.pem"), true)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	defer clear(key)
	ca, e := read(filepath.Join(directory, "ca.pem"), false)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	pair, e := tls.X509KeyPair(certificate, key)
	if e != nil || len(pair.Certificate) == 0 {
		return tls.Certificate{}, nil, ErrCertificate
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || leaf.IsCA {
		return tls.Certificate{}, nil, ErrCertificate
	}
	// 固定开发入口只允许localhost和回环IP，避免误把公网证书/服务私钥装入演示进程。
	for _, name := range leaf.DNSNames {
		if name != "localhost" {
			return tls.Certificate{}, nil, ErrCertificate
		}
	}
	for _, ip := range leaf.IPAddresses {
		if !ip.IsLoopback() {
			return tls.Certificate{}, nil, ErrCertificate
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return tls.Certificate{}, nil, ErrCertificate
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return tls.Certificate{}, nil, ErrCertificate
		}
		intermediates.AddCert(c)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "localhost", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return tls.Certificate{}, nil, ErrCertificate
	}
	if leaf.VerifyHostname("127.0.0.1") != nil {
		return tls.Certificate{}, nil, ErrCertificate
	}
	pair.Leaf = leaf
	return pair, ca, nil
}
func read(path string, private bool) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || (private && before.Mode().Perm()&0077 != 0) {
		return nil, ErrCertificate
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, ErrCertificate
	}
	defer file.Close()
	after, e := file.Stat()
	if e != nil || !os.SameFile(before, after) || (private && after.Mode().Perm()&0077 != 0) {
		return nil, ErrCertificate
	}
	raw, e := io.ReadAll(io.LimitReader(file, 65537))
	if e != nil || len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrCertificate
	}
	return raw, nil
}
