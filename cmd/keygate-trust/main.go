// keygate-trust 提供离线签发、业务签名和固定根客户端验证工具；不输出私钥。
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"ex-keygate/trustchain"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type options struct {
	action, directory, authority, environment, service, audience, rootFile, recoveryPublic, nonce, payload, input, output, origin, caFile string
	version, revision                                                                                                                     uint64
	hours                                                                                                                                 int
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "应用信任链操作失败：", e)
		os.Exit(1)
	}
}
func run() error {
	var o options
	flag.StringVar(&o.action, "action", "", "root-init / recovery-init / key-init / status-init / issue / proposal / pin-init / challenge / sign / verify / recovery-sign / recovery-apply")
	flag.StringVar(&o.directory, "directory", "", "当前角色私有目录")
	flag.StringVar(&o.authority, "authority", "", "离线根或恢复密钥目录")
	flag.StringVar(&o.environment, "environment", "", "固定应用环境")
	flag.StringVar(&o.service, "service", "", "固定业务标识")
	flag.StringVar(&o.audience, "audience", "", "预期接收方用途")
	flag.StringVar(&o.rootFile, "root-file", "", "公开根证书PEM")
	flag.StringVar(&o.recoveryPublic, "recovery-public", "", "预置独立恢复公钥JSON")
	flag.StringVar(&o.nonce, "nonce", "", "客户端本次挑战")
	flag.StringVar(&o.payload, "payload-file", "", "正文文件")
	flag.StringVar(&o.input, "input", "", "公开输入JSON或CSR文件")
	flag.StringVar(&o.output, "output", "", "新输出文件，拒绝覆盖")
	flag.StringVar(&o.origin, "origin", "https://localhost:18761", "开发状态服务HTTPS入口")
	flag.StringVar(&o.caFile, "ca-file", "data/dev-console/ca.pem", "状态服务TLS信任CA")
	flag.Uint64Var(&o.version, "version", 1, "业务证书版本")
	flag.Uint64Var(&o.revision, "revision", 0, "当前权威修订")
	flag.IntVar(&o.hours, "hours", 24, "证书有效小时，最多24小时")
	flag.Parse()
	return execute(o)
}
func output(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	if path != "" {
		return trustchain.WriteNew(path, b)
	}
	_, e = os.Stdout.Write(append(b, '\n'))
	return e
}
func readJSON(path string, v any) error {
	b, e := trustchain.ReadFile(path, false)
	if e != nil {
		return e
	}
	return trustchain.DecodeJSON(b, v)
}
func writeKey(path string, key ed25519.PrivateKey) error {
	b, e := trustchain.PrivateKeyPEM(key)
	if e != nil {
		return e
	}
	defer clear(b)
	return trustchain.WriteNew(path, b)
}
func execute(o options) error {
	now := time.Now().UTC()
	switch o.action {
	case "root-init":
		if trustchain.PrivateDirectory(o.directory, true) != nil {
			return trustchain.ErrInvalid
		}
		root, key, e := trustchain.NewRoot("keygate-application-root", now)
		if e != nil {
			return e
		}
		defer clear(key)
		if e = writeKey(filepath.Join(o.directory, "root.key"), key); e != nil {
			return e
		}
		if e = trustchain.WriteNew(filepath.Join(o.directory, "root.pem"), trustchain.CertificatePEM(root)); e != nil {
			return e
		}
		return output(o.output, map[string]any{"rootFingerprint": trustchain.Fingerprint(root), "developmentOnly": true})
	case "recovery-init":
		if trustchain.PrivateDirectory(o.directory, true) != nil {
			return trustchain.ErrInvalid
		}
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		defer clear(key)
		if e = writeKey(filepath.Join(o.directory, "recovery.key"), key); e != nil {
			return e
		}
		return output(filepath.Join(o.directory, "recovery-public.json"), pub)
	case "key-init":
		if trustchain.PrivateDirectory(o.directory, true) != nil {
			return trustchain.ErrInvalid
		}
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		defer clear(key)
		if e = writeKey(filepath.Join(o.directory, "service.key"), key); e != nil {
			return e
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "application-service"}, SignatureAlgorithm: x509.PureEd25519}, key)
		if e != nil {
			return e
		}
		_ = pub
		return trustchain.WriteNew(filepath.Join(o.directory, "service.csr"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	case "status-init", "issue":
		if o.hours < 1 || o.hours > 24 || trustchain.PrivateDirectory(o.authority, false) != nil || trustchain.PrivateDirectory(o.directory, o.action == "status-init") != nil {
			return trustchain.ErrInvalid
		}
		root, e := trustchain.ReadCertificate(filepath.Join(o.authority, "root.pem"))
		if e != nil {
			return e
		}
		rootKey, e := trustchain.ReadPrivateKey(filepath.Join(o.authority, "root.key"))
		if e != nil {
			return e
		}
		defer clear(rootKey)
		var pub ed25519.PublicKey
		purpose := trustchain.ServicePurpose
		service := o.service
		version := o.version
		if o.action == "status-init" {
			var key ed25519.PrivateKey
			pub, key, e = ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return e
			}
			defer clear(key)
			if e = writeKey(filepath.Join(o.directory, "status.key"), key); e != nil {
				return e
			}
			purpose = trustchain.StatusPurpose
			service = "trust-status"
			version = 1
		} else {
			raw, e := trustchain.ReadFile(filepath.Join(o.directory, "service.csr"), false)
			if e != nil {
				return e
			}
			block, rest := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) > 0 {
				return trustchain.ErrInvalid
			}
			csr, e := x509.ParseCertificateRequest(block.Bytes)
			if e != nil || csr.CheckSignature() != nil {
				return trustchain.ErrInvalid
			}
			var ok bool
			pub, ok = csr.PublicKey.(ed25519.PublicKey)
			if !ok {
				return trustchain.ErrInvalid
			}
		}
		cert, e := trustchain.Issue(root, rootKey, pub, o.environment, purpose, service, version, now, now.Add(time.Duration(o.hours)*time.Hour))
		if e != nil {
			return e
		}
		name := "certificate.pem"
		if o.action == "status-init" {
			name = "status.pem"
			if e = trustchain.WriteNew(filepath.Join(o.directory, "root.pem"), trustchain.CertificatePEM(root)); e != nil {
				return e
			}
			if e = output(filepath.Join(o.directory, "runtime.json"), map[string]string{"environment": o.environment}); e != nil {
				return e
			}
		}
		return trustchain.WriteNew(filepath.Join(o.directory, name), trustchain.CertificatePEM(cert))
	case "proposal":
		root, e := trustchain.ReadCertificate(o.rootFile)
		if e != nil {
			return e
		}
		certificate, e := trustchain.ReadCertificate(filepath.Join(o.directory, "certificate.pem"))
		if e != nil {
			return e
		}
		key, e := trustchain.ReadPrivateKey(filepath.Join(o.directory, "service.key"))
		if e != nil {
			return e
		}
		defer clear(key)
		pub, e := trustchain.VerifyCertificate(root, certificate, o.environment, trustchain.ServicePurpose, o.service, o.version, now)
		if e != nil || !pub.Equal(key.Public()) {
			return trustchain.ErrInvalid
		}
		return output(o.output, map[string]any{"kind": "trust_certificate_publish", "clientId": o.service, "expectedRevision": fmt.Sprint(o.revision), "keyVersion": fmt.Sprint(o.version), "name": "", "profileId": "", "profileVersion": "0", "trustRootFingerprint": trustchain.Fingerprint(root), "trustCertificate": certificate, "trustProof": trustchain.PossessionProof(certificate, key)})
	case "pin-init":
		root, e := trustchain.ReadCertificate(o.rootFile)
		if e != nil {
			return e
		}
		var recovery []byte
		if e = readJSON(o.recoveryPublic, &recovery); e != nil {
			return e
		}
		return trustchain.InitializeClient(o.directory, trustchain.Pins{Root: root, RecoveryPublicKey: recovery, Epoch: 1, Environment: o.environment, ServiceID: o.service, Audience: o.audience}, now)
	case "challenge":
		s, e := trustchain.OpenClient(o.directory)
		if e != nil {
			return e
		}
		defer s.Close()
		nonce, e := s.Challenge(now)
		if e != nil {
			return e
		}
		return output(o.output, map[string]string{"nonce": nonce})
	case "sign":
		root, e := trustchain.ReadCertificate(o.rootFile)
		if e != nil {
			return e
		}
		certificate, e := trustchain.ReadCertificate(filepath.Join(o.directory, "certificate.pem"))
		if e != nil {
			return e
		}
		key, e := trustchain.ReadPrivateKey(filepath.Join(o.directory, "service.key"))
		if e != nil {
			return e
		}
		defer clear(key)
		payload, e := readPayload(o.payload)
		if e != nil || len(payload) > 1<<20 {
			return trustchain.ErrInvalid
		}
		message, e := trustchain.SignMessage(root, certificate, key, o.environment, o.service, o.version, o.audience, o.nonce, payload, now)
		if e != nil {
			return e
		}
		return output(o.output, message)
	case "verify":
		s, e := trustchain.OpenClient(o.directory)
		if e != nil {
			return e
		}
		defer s.Close()
		var message trustchain.Message
		if e = readJSON(o.input, &message); e != nil {
			return e
		}
		payload, e := readPayload(o.payload)
		if e != nil || len(payload) > 1<<20 {
			return trustchain.ErrInvalid
		}
		status, e := getStatus(o, s.Pins, o.nonce)
		if e != nil {
			return e
		}
		if e = s.Verify(message, status, o.nonce, payload, time.Now()); e != nil {
			return e
		}
		return output(o.output, map[string]any{"verified": true, "version": message.Version, "revision": status.Revision})
	case "recovery-sign":
		s, e := trustchain.OpenClient(o.directory)
		if e != nil {
			return e
		}
		defer s.Close()
		root, e := trustchain.ReadCertificate(o.rootFile)
		if e != nil {
			return e
		}
		key, e := trustchain.ReadPrivateKey(filepath.Join(o.authority, "recovery.key"))
		if e != nil {
			return e
		}
		defer clear(key)
		update, e := trustchain.SignRecovery(s.Pins, root, key, now)
		if e != nil {
			return e
		}
		return output(o.output, update)
	case "recovery-apply":
		s, e := trustchain.OpenClient(o.directory)
		if e != nil {
			return e
		}
		defer s.Close()
		var update trustchain.RecoveryUpdate
		if e = readJSON(o.input, &update); e != nil {
			return e
		}
		return s.Recover(update, now)
	default:
		return errors.New("未知操作")
	}
}
func getStatus(o options, p trustchain.Pins, nonce string) (trustchain.Status, error) {
	u, e := url.Parse(o.origin)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		return trustchain.Status{}, trustchain.ErrInvalid
	}
	ca, e := trustchain.ReadFile(o.caFile, false)
	if e != nil {
		return trustchain.Status{}, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return trustchain.Status{}, trustchain.ErrInvalid
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return trustchain.ErrInvalid }}
	body, _ := json.Marshal(map[string]string{"nonce": nonce, "audience": p.Audience})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "POST", o.origin+"/api/trust/"+url.PathEscape(p.ServiceID)+"/status", bytes.NewReader(body))
	if e != nil {
		return trustchain.Status{}, e
	}
	request.Header.Set("Content-Type", "application/json")
	response, e := client.Do(request)
	if e != nil {
		return trustchain.Status{}, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return trustchain.Status{}, errors.New("状态服务不可用，拒绝认证")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return trustchain.Status{}, trustchain.ErrInvalid
	}
	var status trustchain.Status
	if e = trustchain.DecodeJSON(raw, &status); e != nil {
		return status, e
	}
	return status, nil
}

func readPayload(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, trustchain.ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return nil, trustchain.ErrInvalid
	}
	return b, nil
}
