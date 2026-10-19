package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// HTTPConfig 只能由受控启动配置提供；端点/IP/信任根与客户端证书不能由管理请求指定。
type HTTPConfig struct {
	Descriptor  Descriptor
	Endpoint    string
	AllowedIPs  []netip.Addr
	Roots       *x509.CertPool
	Certificate tls.Certificate
}
type HTTPVerifier struct {
	descriptor Descriptor
	endpoint   string
	client     *http.Client
}
type WireVerification struct {
	ProtocolVersion string       `json:"protocolVersion"`
	ProviderID      string       `json:"providerId"`
	ProviderVersion string       `json:"providerVersion"`
	RequestID       string       `json:"requestId"`
	Environment     string       `json:"environment"`
	ClientID        string       `json:"clientId"`
	Audience        string       `json:"audience"`
	Purpose         string       `json:"purpose"`
	Key             KeyReference `json:"key"`
	Algorithm       string       `json:"algorithm"`
	Payload         []byte       `json:"payload"`
	Proof           []byte       `json:"proof"`
}
type WireResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ProviderID      string `json:"providerId"`
	ProviderVersion string `json:"providerVersion"`
	RequestID       string `json:"requestId"`
	RequestDigest   string `json:"requestDigest"`
	Verified        *bool  `json:"verified"`
}
type WireHealth struct {
	ProtocolVersion string `json:"protocolVersion"`
	ProviderID      string `json:"providerId"`
	ProviderVersion string `json:"providerVersion"`
	Ready           *bool  `json:"ready"`
}

func NewHTTPVerifier(c HTTPConfig) (*HTTPVerifier, error) {
	if c.Descriptor.Validate() != nil || c.Descriptor.Kind != ThirdParty || len(c.Descriptor.Capabilities) != 1 || c.Descriptor.Capabilities[0] != Verify || c.Roots == nil || len(c.Certificate.Certificate) == 0 || c.Certificate.PrivateKey == nil || len(c.AllowedIPs) < 1 || len(c.AllowedIPs) > 4 {
		return nil, ErrInvalid
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return nil, ErrInvalid
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, ErrInvalid
	}
	pins := append([]netip.Addr(nil), c.AllowedIPs...)
	for _, ip := range pins {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, ErrInvalid
		}
	}
	if literal, e := netip.ParseAddr(host); e == nil {
		found := false
		for _, p := range pins {
			if p == literal {
				found = true
			}
		}
		if !found {
			return nil, ErrInvalid
		}
	}
	// 固定拨号白名单并关闭代理与重定向，不能通过 DNS 重绑定、代理环境或 30x 访问未批准端点。
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.Roots.Clone(), Certificates: []tls.Certificate{cloneCertificate(c.Certificate)}, ServerName: host, NextProtos: []string{"http/1.1"}}, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: false}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		expected := net.JoinHostPort(host, port)
		if address != expected {
			return nil, ErrUnavailable
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
		return nil, ErrUnavailable
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable }}
	descriptor := c.Descriptor
	descriptor.Capabilities = append([]Capability(nil), c.Descriptor.Capabilities...)
	return &HTTPVerifier{descriptor: descriptor, endpoint: c.Endpoint, client: client}, nil
}
func cloneCertificate(c tls.Certificate) tls.Certificate {
	out := c
	out.Certificate = make([][]byte, len(c.Certificate))
	for i, b := range c.Certificate {
		out.Certificate[i] = append([]byte(nil), b...)
	}
	out.OCSPStaple = append([]byte(nil), c.OCSPStaple...)
	out.SignedCertificateTimestamps = nil
	return out
}
func (p *HTTPVerifier) Close() { p.client.CloseIdleConnections() }
func (p *HTTPVerifier) Descriptor() Descriptor {
	d := p.descriptor
	d.Capabilities = append([]Capability(nil), d.Capabilities...)
	return d
}
func validVerification(v Verification) bool {
	for _, id := range []string{v.RequestID, v.Environment, v.ClientID, v.Audience, v.Purpose, v.Key.ID, v.Algorithm} {
		if !identifier.MatchString(id) {
			return false
		}
	}
	return v.Key.Version > 0 && v.Key.Version <= 9007199254740991 && len(v.Payload) > 0 && len(v.Payload) <= 65536 && len(v.Proof) > 0 && len(v.Proof) <= 512
}

// Verify 只执行无副作用的证明核验；授权、真实请求绑定、状态、防重放及最终放行仍由主服务负责。
func (p *HTTPVerifier) Verify(ctx context.Context, v Verification) error {
	if !validVerification(v) {
		return ErrInvalid
	}
	in := WireVerification{ProtocolVersion, p.descriptor.ID, p.descriptor.Version, v.RequestID, v.Environment, v.ClientID, v.Audience, v.Purpose, v.Key, v.Algorithm, v.Payload, v.Proof}
	raw, e := json.Marshal(in)
	if e != nil {
		return ErrInvalid
	}
	out := WireResult{}
	if e = p.exchange(ctx, "POST", "/v1/verify", raw, &out); e != nil {
		return e
	}
	digest := sha256.Sum256(raw)
	if out.ProtocolVersion != ProtocolVersion || out.ProviderID != p.descriptor.ID || out.ProviderVersion != p.descriptor.Version || out.RequestID != v.RequestID || out.RequestDigest != hex.EncodeToString(digest[:]) || out.Verified == nil {
		return ErrUnavailable
	}
	if !*out.Verified {
		return ErrRejected
	}
	return nil
}
func (p *HTTPVerifier) CheckHealth(ctx context.Context) error {
	out := WireHealth{}
	if e := p.exchange(ctx, "GET", "/v1/health", nil, &out); e != nil {
		return e
	}
	if out.ProtocolVersion != ProtocolVersion || out.ProviderID != p.descriptor.ID || out.ProviderVersion != p.descriptor.Version || out.Ready == nil || !*out.Ready {
		return ErrUnavailable
	}
	return nil
}
func (p *HTTPVerifier) exchange(ctx context.Context, method, path string, raw []byte, out any) error {
	r, e := http.NewRequestWithContext(ctx, method, p.endpoint+path, bytes.NewReader(raw))
	if e != nil {
		return ErrInvalid
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Accept", "application/json")
	response, e := p.client.Do(r)
	if e != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 16385))
	if e != nil || len(body) > 16384 || response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Encoding") != "" {
		return ErrUnavailable
	}
	allowed := []string{"protocolVersion", "providerId", "providerVersion"}
	switch out.(type) {
	case *WireHealth:
		allowed = append(allowed, "ready")
	case *WireResult:
		allowed = append(allowed, "requestId", "requestDigest", "verified")
	default:
		return ErrInvalid
	}
	if !exactWireFields(body, allowed...) || DecodeStrict(body, out) != nil {
		return ErrUnavailable
	}
	return nil
}

// DecodeStrict 远程契约拒绝重复/未知字段及尾随数据；避免两个解码器对证明结果产生不同解释。
func DecodeStrict(raw []byte, out any) error {
	if !utf8.Valid(raw) || !validWireEscapes(raw) || !wireFields(raw, reflect.TypeOf(out)) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if e := uniqueWire(d, 0); e != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return ErrInvalid
	}
	return nil
}
func uniqueWire(d *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrInvalid
	}
	token, e := d.Token()
	if e != nil {
		return ErrInvalid
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return ErrInvalid
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return ErrInvalid
			}
			seen[s] = true
			if e = uniqueWire(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
		return nil
	}
	if delim == '[' {
		for d.More() {
			if e = uniqueWire(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return ErrInvalid
		}
		return nil
	}
	return ErrInvalid
}

// 只允许固定协议的精确字段大小写，避免 Go 解码器默认接受别名覆盖。
func exactWireFields(raw []byte, allowed ...string) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return false
	}
	for d.More() {
		t, e := d.Token()
		if e != nil {
			return false
		}
		key, ok := t.(string)
		if !ok {
			return false
		}
		found := false
		for _, a := range allowed {
			if key == a {
				found = true
			}
		}
		if !found {
			return false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
	}
	return true
}

var _ Verifier = (*HTTPVerifier)(nil)
var _ HealthChecker = (*HTTPVerifier)(nil)

func wireFields(raw []byte, t reflect.Type) bool {
	if t == nil {
		return false
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	allowed := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" {
			name = field.Name
		}
		if name != "-" && field.PkgPath == "" {
			allowed[name] = field.Type
		}
	}
	for name, value := range fields {
		typ, ok := allowed[name]
		if !ok || !wireFields(value, typ) {
			return false
		}
	}
	return true
}
func validWireEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			lo, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || lo < 0xdc00 || lo > 0xdfff {
				return false
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
	}
	return true
}
