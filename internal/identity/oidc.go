// Package identity verifies OIDC login results; it does not expose ID tokens as API credentials.
package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var ErrIdentity = errors.New("identity verification failed")
var ErrConfig = errors.New("invalid identity configuration")

type Config struct {
	TrustedRoots    *x509.CertPool
	DevelopmentMode bool
	Issuer          string
	JWKSURL         string
	ClientID        string
	AllowedACR      []string
	RequiredAMR     []string
	MaxAuthAge      time.Duration
}

func (c Config) validate() error {
	issuer, err := url.Parse(c.Issuer)
	if err != nil || !secureURL(issuer) {
		return ErrConfig
	}
	keys, err := url.Parse(c.JWKSURL)
	if err != nil || !secureURL(keys) || keys.Host != issuer.Host {
		return ErrConfig
	}
	if strings.TrimSpace(c.ClientID) == "" || len(c.ClientID) > 256 || c.MaxAuthAge < time.Second || c.MaxAuthAge > 5*time.Minute || len(c.AllowedACR) == 0 {
		return ErrConfig
	}
	for _, acr := range c.AllowedACR {
		if strings.TrimSpace(acr) == "" || len(acr) > 256 || (strings.HasPrefix(acr, "urn:keygate:dev:") && !c.DevelopmentMode) {
			return ErrConfig
		}
	}
	// AMR 是身份平台声明的认证方式；要求全部命中配置，不能只因列表里出现 mfa 就自动放行。
	if len(c.RequiredAMR) > 16 {
		return ErrConfig
	}
	seen := map[string]bool{}
	for _, method := range c.RequiredAMR {
		if method == "" || len(method) > 128 || strings.ContainsAny(method, " \t\r\n") || seen[method] || (!c.DevelopmentMode && method == "mock") {
			return ErrConfig
		}
		seen[method] = true
	}
	return nil
}
func secureURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	response.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(response.Body, 1<<20), response.Body}
	return response, nil
}

type OIDC struct {
	config   Config
	verifier *oidc.IDTokenVerifier
	now      func() time.Time
}

func NewOIDC(c Config) (*OIDC, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	client := oidcHTTPClient()
	if c.TrustedRoots != nil {
		client.Transport.(boundedTransport).base.(*http.Transport).TLSClientConfig.RootCAs = c.TrustedRoots.Clone()
	}
	ctx := oidc.ClientContext(context.Background(), client)
	keys := oidc.NewRemoteKeySet(ctx, c.JWKSURL)
	return newOIDC(c, keys, time.Now), nil
}
func oidcHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxIdleConns: 8, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second,
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: boundedTransport{transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func newOIDC(c Config, keys oidc.KeySet, now func() time.Time) *OIDC {
	c.AllowedACR = slices.Clone(c.AllowedACR)
	c.RequiredAMR = slices.Clone(c.RequiredAMR)
	return &OIDC{c, oidc.NewVerifier(c.Issuer, keys, &oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.PS256, oidc.ES256}, Now: now}), now}
}

type Principal struct {
	ID              string
	AuthenticatedAt time.Time
}

// VerifyLogin 只处理可信授权码回调；调用方先核验 state/PKCE 并一次性消费服务端 nonce，再建立会话。
// nonce 不能取自未经验证的请求声明；MFA 结果必须来自签名 ID Token。
func (v *OIDC) VerifyLogin(ctx context.Context, raw, expectedNonce string) (Principal, error) {
	if v == nil || v.verifier == nil || len(raw) > 16384 {
		return Principal{}, ErrIdentity
	}
	nonce, err := base64.RawURLEncoding.DecodeString(expectedNonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != expectedNonce {
		return Principal{}, ErrIdentity
	}
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return Principal{}, ErrIdentity
	}
	now := v.now()
	// 额外拒绝签发者别名、过期边界、缺失时间与过长有效期，不能因库的兼容规则而放宽认证。
	if token.Issuer != v.config.Issuer || token.Subject == "" || len(token.Subject) > 1024 || token.IssuedAt.IsZero() || token.IssuedAt.After(now.Add(30*time.Second)) || !now.Before(token.Expiry) || !token.Expiry.After(token.IssuedAt) || token.Expiry.Sub(token.IssuedAt) > 5*time.Minute || subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(expectedNonce)) != 1 {
		return Principal{}, ErrIdentity
	}
	var claims struct {
		ACR       string   `json:"acr"`
		AMR       []string `json:"amr"`
		AuthTime  int64    `json:"auth_time"`
		AZP       string   `json:"azp"`
		NotBefore int64    `json:"nbf"`
	}
	if token.Claims(&claims) != nil || !slices.Contains(v.config.AllowedACR, claims.ACR) || claims.AuthTime <= 0 {
		return Principal{}, ErrIdentity
	}
	for _, required := range v.config.RequiredAMR {
		if !slices.Contains(claims.AMR, required) {
			return Principal{}, ErrIdentity
		}
	}
	authTime := time.Unix(claims.AuthTime, 0)
	if authTime.After(now.Add(30*time.Second)) || now.Sub(authTime) >= v.config.MaxAuthAge || authTime.After(token.IssuedAt.Add(30*time.Second)) || (claims.NotBefore > 0 && now.Before(time.Unix(claims.NotBefore, 0))) {
		return Principal{}, ErrIdentity
	}
	if (len(token.Audience) > 1 && claims.AZP != v.config.ClientID) || (claims.AZP != "" && claims.AZP != v.config.ClientID) {
		return Principal{}, ErrIdentity
	}
	// 身份绑定 issuer 与不可变 subject，统一供登录和离线人员登记使用。
	return Principal{PrincipalID(token.Issuer, token.Subject), authTime}, nil
}

// PrincipalID 统一外部身份主键；调用方须先验证 issuer 和 subject 的来源与格式。
func PrincipalID(issuer, subject string) string {
	encoded, _ := json.Marshal([]string{issuer, subject})
	sum := sha256.Sum256(encoded)
	return "oidc-" + hex.EncodeToString(sum[:])
}
