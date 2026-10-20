package mfa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"ex-keygate/provider"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

var ErrPlugin = errors.New("MFA plugin unavailable or verification denied")

type HTTPSPlugin struct {
	base   string
	client *http.Client
}

// NewHTTPSPlugin 固定插件源、专用CA和双向TLS；不接受请求指定端点，不跟随重定向，也不回显远端错误正文。
func NewHTTPSPlugin(base string, roots *x509.CertPool, certificate tls.Certificate, pins []netip.Addr) (*HTTPSPlugin, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || roots == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil || len(pins) == 0 || len(pins) > 4 {
		return nil, ErrInvalid
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, ErrInvalid
	}
	pins = append([]netip.Addr(nil), pins...)
	found := false
	for _, ip := range pins {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, ErrInvalid
		}
		if ip.String() == host {
			found = true
		}
	}
	if _, e := netip.ParseAddr(host); e == nil && !found {
		return nil, ErrInvalid
	}
	copied := certificate
	copied.Certificate = make([][]byte, len(certificate.Certificate))
	for i, b := range certificate.Certificate {
		copied.Certificate[i] = append([]byte(nil), b...)
	}
	copied.OCSPStaple = append([]byte(nil), certificate.OCSPStaple...)
	copied.SignedCertificateTimestamps = nil
	transport := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots.Clone(), Certificates: []tls.Certificate{copied}, ServerName: host}, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	dialer := &net.Dialer{Timeout: time.Second}
	// 固定IP拨号、TLS主机名和专用CA一起约束目标，防止DNS重绑定和代理环境改变验证服务。
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort(host, port) {
			return nil, ErrPlugin
		}
		for _, ip := range pins {
			conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, ErrPlugin
	}

	return &HTTPSPlugin{base, &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (p *HTTPSPlugin) call(ctx context.Context, path, id string, input, output any) error {
	raw, e := json.Marshal(input)
	if e != nil || len(raw) > 65536 {
		return ErrPlugin
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, p.base+path, bytes.NewReader(raw))
	if e != nil {
		return ErrPlugin
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", id)
	response, e := p.client.Do(req)
	if e != nil {
		return ErrPlugin
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/json" {
		return ErrPlugin
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(body) > 65536 {
		return ErrPlugin
	}
	// 外层摘要绑定完整请求，防止相同ID的历史结果被用于不同challenge或proof；内外层均严格解码。
	var envelope struct {
		RequestDigest string          `json:"requestDigest"`
		Result        json.RawMessage `json:"result"`
	}
	digest := sha256.Sum256(raw)
	if provider.DecodeStrict(body, &envelope) != nil || envelope.RequestDigest != hex.EncodeToString(digest[:]) || provider.DecodeStrict(envelope.Result, output) != nil {
		return ErrPlugin
	}

	return nil
}
func (p *HTTPSPlugin) Send(ctx context.Context, d Delivery) error {
	var out struct {
		ID       string `json:"id"`
		Accepted bool   `json:"accepted"`
	}
	if e := p.call(ctx, "/deliver", d.ID, d, &out); e != nil || out.ID != d.ID || !out.Accepted {
		return ErrPlugin
	}
	return nil
}
func (p *HTTPSPlugin) Begin(ctx context.Context, c HardwareChallenge) (json.RawMessage, error) {
	var out struct {
		ID      string          `json:"id"`
		Options json.RawMessage `json:"options"`
	}
	if e := p.call(ctx, "/hardware/begin", c.ID, c, &out); e != nil || out.ID != c.ID || len(out.Options) == 0 || bytes.Equal(out.Options, []byte("null")) {
		return nil, ErrPlugin
	}
	return out.Options, nil
}
func (p *HTTPSPlugin) Verify(ctx context.Context, c HardwareChallenge, proof json.RawMessage) error {
	var out struct {
		ID       string `json:"id"`
		Verified bool   `json:"verified"`
	}
	input := struct {
		Challenge HardwareChallenge `json:"challenge"`
		Proof     json.RawMessage   `json:"proof"`
	}{c, proof}
	if e := p.call(ctx, "/hardware/verify", c.ID, input, &out); e != nil || out.ID != c.ID || !out.Verified {
		return ErrPlugin
	}
	return nil
}

func (p *HTTPSPlugin) Close() { p.client.CloseIdleConnections() }

func (p *HTTPSPlugin) RegisterBegin(ctx context.Context, c HardwareChallenge) (json.RawMessage, error) {
	var out struct {
		ID      string          `json:"id"`
		Options json.RawMessage `json:"options"`
	}
	if e := p.call(ctx, "/hardware/register/begin", c.ID, c, &out); e != nil || out.ID != c.ID || len(out.Options) == 0 || bytes.Equal(out.Options, []byte("null")) {
		return nil, ErrPlugin
	}
	return out.Options, nil
}
func (p *HTTPSPlugin) RegisterVerify(ctx context.Context, c HardwareChallenge, proof json.RawMessage) (string, error) {
	var out struct {
		ID         string `json:"id"`
		Credential string `json:"credential"`
		Verified   bool   `json:"verified"`
	}
	input := struct {
		Challenge HardwareChallenge `json:"challenge"`
		Proof     json.RawMessage   `json:"proof"`
	}{c, proof}
	if e := p.call(ctx, "/hardware/register/verify", c.ID, input, &out); e != nil || out.ID != c.ID || !out.Verified || len(out.Credential) == 0 || len(out.Credential) > 2048 {
		return "", ErrPlugin
	}
	return out.Credential, nil
}
