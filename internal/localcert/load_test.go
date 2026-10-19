package localcert

import (
	"crypto/x509"
	"encoding/pem"
	"ex-keygate/internal/devtls"
	"os"
	"testing"
)

func TestPersistentLoopbackCertificate(t *testing.T) {
	cert, ca, e := devtls.Certificate("local certificate test")
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	for name, raw := range map[string][]byte{"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), "ca.pem": ca} {
		if e = os.WriteFile(dir+"/"+name, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	loaded, _, e := Load(dir)
	if e != nil || loaded.Leaf == nil {
		t.Fatal("有效证书未加载", e)
	}
	if e = os.Chmod(dir+"/key.pem", 0644); e != nil {
		t.Fatal(e)
	}
	if _, _, e = Load(dir); e == nil {
		t.Fatal("公开可读私钥被接受")
	}
	os.Chmod(dir+"/key.pem", 0600)
	_, wrongCA, e := devtls.Certificate("other")
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(dir+"/ca.pem", wrongCA, 0600)
	if _, _, e = Load(dir); e == nil {
		t.Fatal("错误CA被接受")
	}
	os.Remove(dir + "/key.pem")
	os.Symlink(dir+"/cert.pem", dir+"/key.pem")
	if _, _, e = Load(dir); e == nil {
		t.Fatal("链接私钥被接受")
	}
}
