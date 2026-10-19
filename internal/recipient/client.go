// Package recipient 为开发后端提供独立接收方密钥、受控交付和实际请求签名。
// 私钥和共享密钥只能留在接收方本机，不进入管理页面或服务日志。
package recipient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"ex-keygate/internal/access"
	"ex-keygate/internal/httpsign"
	"ex-keygate/internal/manifest"
)

var ErrDelivery = errors.New("development recipient validation failed")

type Identity struct{ Encryption, Signing []byte }
type PublicConfig struct {
	Encryption            string `json:"recipientPublicKey"`
	EncryptionFingerprint string `json:"recipientFingerprint"`
	Signing               string `json:"recipientSigningKey"`
	SigningFingerprint    string `json:"recipientSigningFingerprint"`
}
type Scope struct {
	Environment, ClientID, IssueID string
	Version                        uint64
}
type Credential struct {
	Scope                   Scope
	Origin                  string
	Secret, PossessionInput []byte
}
type Client struct {
	origin     string
	http       *http.Client
	encryption *rsa.PrivateKey
	signing    ed25519.PrivateKey
	public     PublicConfig
}

func Generate() (Identity, error) {
	key, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		return Identity{}, e
	}
	_, signing, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return Identity{}, e
	}
	encryptionDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return Identity{}, e
	}
	signingDER, e := x509.MarshalPKCS8PrivateKey(signing)
	if e != nil {
		return Identity{}, e
	}
	return Identity{encryptionDER, signingDER}, nil
}
func fingerprint(der []byte) string { h := sha256.Sum256(der); return hex.EncodeToString(h[:]) }
func parseIdentity(identity Identity) (*rsa.PrivateKey, ed25519.PrivateKey, PublicConfig, error) {
	encryption, e := x509.ParsePKCS8PrivateKey(identity.Encryption)
	if e != nil {
		return nil, nil, PublicConfig{}, ErrDelivery
	}
	rsaKey, ok := encryption.(*rsa.PrivateKey)
	if !ok || (rsaKey.N.BitLen() != 3072 && rsaKey.N.BitLen() != 4096) || rsaKey.E != 65537 || rsaKey.Validate() != nil {
		return nil, nil, PublicConfig{}, ErrDelivery
	}
	signing, e := x509.ParsePKCS8PrivateKey(identity.Signing)
	if e != nil {
		return nil, nil, PublicConfig{}, ErrDelivery
	}
	edKey, ok := signing.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, PublicConfig{}, ErrDelivery
	}
	der, e := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if e != nil {
		return nil, nil, PublicConfig{}, e
	}
	edDER, e := x509.MarshalPKIXPublicKey(edKey.Public())
	if e != nil {
		return nil, nil, PublicConfig{}, e
	}
	return rsaKey, edKey, PublicConfig{base64.RawStdEncoding.EncodeToString(der), fingerprint(der), base64.RawStdEncoding.EncodeToString(edDER), fingerprint(edDER)}, nil
}
func Public(identity Identity) (PublicConfig, error) {
	_, _, p, e := parseIdentity(identity)
	return p, e
}

// New 固定受信本机 TLS 地址与 CA，不跟随重定向、不使用环境代理，防止跨地址发送持有证明。
func New(origin string, ca []byte, identity Identity) (*Client, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, ErrDelivery
	}
	ip := net.ParseIP(u.Hostname())
	if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, ErrDelivery
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrDelivery
	}
	rsaKey, edKey, public, e := parseIdentity(identity)
	if e != nil {
		return nil, e
	}
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{origin, httpClient, rsaKey, edKey, public}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) call(ctx context.Context, method, path string, input, output any) error {
	var raw []byte
	var e error
	if input != nil {
		raw, e = json.Marshal(input)
		if e != nil {
			return e
		}
	}
	r, e := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, e := c.http.Do(r)
	if e != nil {
		return errors.New("trusted development endpoint unavailable")
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(body) > 65536 {
		return ErrDelivery
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("development endpoint rejected request: HTTP %d", response.StatusCode)
	}
	if output != nil {
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		if e = d.Decode(output); e != nil {
			return ErrDelivery
		}
		if d.Decode(&struct{}{}) != io.EOF {
			return ErrDelivery
		}
	}
	return nil
}

type deliveryContext struct {
	ClientID              string `json:"clientId"`
	Environment           string `json:"environment"`
	IssueID               string `json:"issueId"`
	Nonce                 string `json:"nonce"`
	Purpose               string `json:"purpose"`
	EncryptionFingerprint string `json:"recipientFingerprint"`
	SigningFingerprint    string `json:"recipientSigningFingerprint"`
	Version               string `json:"version"`
}

func validScope(s Scope) bool {
	return access.ValidID(s.Environment) && access.ValidID(s.ClientID) && access.ValidID(s.IssueID) && s.Version > 0 && s.Version <= 9007199254740991
}

// context 先核对目标、用途、两把本机公钥及规范编码，再允许签名或使用客户端秘密。
func (c *Client) context(raw []byte, s Scope, purpose string) error {
	if !validScope(s) || len(raw) > 4096 {
		return ErrDelivery
	}
	var input deliveryContext
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		return ErrDelivery
	}
	canonical, e := manifest.Canonical(input)
	if e != nil || !bytes.Equal(canonical, raw) || input.Environment != s.Environment || input.ClientID != s.ClientID || input.IssueID != s.IssueID || input.Version != strconv.FormatUint(s.Version, 10) || input.Purpose != purpose || input.EncryptionFingerprint != c.public.EncryptionFingerprint || input.SigningFingerprint != c.public.SigningFingerprint {
		return ErrDelivery
	}
	if purpose == "keygate-delivery-wrap-v1" {
		if input.Nonce != "" {
			return ErrDelivery
		}
	} else {
		nonce, e := base64.RawURLEncoding.DecodeString(input.Nonce)
		if e != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != input.Nonce {
			return ErrDelivery
		}
	}
	return nil
}
func (c *Client) Claim(ctx context.Context, s Scope) (Credential, error) {
	if !validScope(s) {
		return Credential{}, ErrDelivery
	}
	var challenge struct {
		Input []byte `json:"input"`
	}
	path := "/api/deliveries/" + s.IssueID
	if e := c.call(ctx, "GET", path+"/challenge", nil, &challenge); e != nil {
		return Credential{}, e
	}
	if e := c.context(challenge.Input, s, "keygate-delivery-claim-v1"); e != nil {
		return Credential{}, e
	}
	signature := ed25519.Sign(c.signing, challenge.Input)
	var bundle struct {
		Ciphertext      []byte `json:"ciphertext"`
		OAEPLabel       []byte `json:"oaepLabel"`
		PossessionInput []byte `json:"possessionInput"`
	}
	if e := c.call(ctx, "POST", path+"/claim", map[string]any{"signature": signature}, &bundle); e != nil {
		return Credential{}, e
	}
	if c.context(bundle.OAEPLabel, s, "keygate-delivery-wrap-v1") != nil || c.context(bundle.PossessionInput, s, "keygate-enrollment-v1") != nil || len(bundle.Ciphertext) != c.encryption.Size() {
		return Credential{}, ErrDelivery
	}
	secret, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.encryption, bundle.Ciphertext, bundle.OAEPLabel)
	if e != nil || len(secret) != 32 {
		clear(secret)
		return Credential{}, ErrDelivery
	}
	return Credential{Scope: s, Origin: c.origin, Secret: secret, PossessionInput: bundle.PossessionInput}, nil
}
func (c *Client) Confirm(ctx context.Context, credential Credential) error {
	if credential.Origin != c.origin || len(credential.Secret) != 32 || c.context(credential.PossessionInput, credential.Scope, "keygate-enrollment-v1") != nil {
		return ErrDelivery
	}
	mac := hmac.New(sha256.New, credential.Secret)
	mac.Write(credential.PossessionInput)
	return c.call(ctx, "POST", "/api/deliveries/"+credential.Scope.IssueID+"/confirm", map[string]any{"mac": mac.Sum(nil)}, nil)
}

// Probe 返回服务端状态码，401 是认证拒绝而不是网络失败；输出不包含可复用客户端秘密。
func (c *Client) Probe(ctx context.Context, credential Credential) (int, error) {
	if !validScope(credential.Scope) || credential.Origin != c.origin || len(credential.Secret) != 32 {
		return 0, ErrDelivery
	}
	body := []byte(`{"probe":true}`)
	r, e := http.NewRequestWithContext(ctx, "POST", c.origin+"/api/auth/probe", bytes.NewReader(body))
	if e != nil {
		return 0, e
	}
	now := time.Now().Unix()
	m := httpsign.Message{ClientID: credential.Scope.ClientID, Version: credential.Scope.Version, Environment: credential.Scope.Environment, Audience: "keygate-probe", Created: now, Expires: now + 60}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return 0, e
	}
	m.RequestID = hex.EncodeToString(id[:])
	if _, e = rand.Read(m.Nonce[:]); e != nil {
		return 0, e
	}
	if e = httpsign.Sign(r, body, credential.Secret, m); e != nil {
		return 0, e
	}
	response, e := c.http.Do(r)
	if e != nil {
		return 0, errors.New("trusted development endpoint unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, nil
}
