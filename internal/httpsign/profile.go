// Package httpsign 实现固定且严格的 RFC 9421 HMAC 请求签名 Profile。
// 仅接受本文约定的单签名和规范编码，不尝试容忍未知 Profile 或算法降级。
package httpsign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var ErrSignature = errors.New("invalid HTTP message signature")

const MaxBody = 1 << 20
const components = `("@method" "@scheme" "@authority" "@path" "@query" "content-digest" "content-type" "x-keygate-client" "x-keygate-key-version" "x-keygate-audience" "x-keygate-environment" "x-keygate-request-id")`

var id = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var paramsPattern = regexp.MustCompile(`^;created=([0-9]{1,16});expires=([0-9]{1,16});nonce="([A-Za-z0-9_-]{43})";keyid="([a-zA-Z0-9][a-zA-Z0-9._-]{0,127})/([1-9][0-9]{0,15})";alg="hmac-sha256";tag="ex-keygate-auth-v1"$`)
var headers = []string{"Content-Digest", "Content-Type", "X-Keygate-Client", "X-Keygate-Key-Version", "X-Keygate-Audience", "X-Keygate-Environment", "X-Keygate-Request-Id", "Signature-Input", "Signature"}

type Message struct {
	ClientID, Environment, Audience, RequestID string
	Version                                    uint64
	Created, Expires                           int64
	Nonce                                      [32]byte
	Base, MAC                                  []byte
}

func decimal(s string) (int64, error) {
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < 0 || n > 9007199254740991 || strconv.FormatInt(n, 10) != s {
		return 0, ErrSignature
	}
	return n, nil
}
func one(r *http.Request, key string) (string, error) {
	values := r.Header.Values(key)
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] || strings.ContainsAny(values[0], "\r\n\t") {
		return "", ErrSignature
	}
	return values[0], nil
}
func Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// target 只从实际 HTTP 请求取得目标，不使用转发头；调用方必须在可信 TLS 入口验证。
// RFC 的 @authority 使用小写主机并移除 HTTPS 默认端口，@query 保留原始编码和前导问号。
func target(r *http.Request) (string, string, string, error) {
	if r.URL == nil || r.URL.Opaque != "" || r.URL.Fragment != "" || r.URL.User != nil || r.URL.Scheme != "" && r.URL.Scheme != "https" {
		return "", "", "", ErrSignature
	}
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	if authority == "" || r.URL.Host != "" && !strings.EqualFold(r.URL.Host, authority) {
		return "", "", "", ErrSignature
	}
	u, e := url.Parse("https://" + authority)
	if e != nil || u.Host != authority || u.User != nil || u.RawQuery != "" || u.Path != "" || u.Fragment != "" || u.Hostname() == "" {
		return "", "", "", ErrSignature
	}
	authority = strings.ToLower(authority)
	if strings.HasSuffix(authority, ":443") {
		authority = strings.TrimSuffix(authority, ":443")
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "", "", "", ErrSignature
	}
	if r.RequestURI != "" && r.RequestURI != r.URL.RequestURI() {
		return "", "", "", ErrSignature
	}
	for _, s := range []string{path, r.URL.RawQuery} {
		for _, b := range []byte(s) {
			if b < 33 || b > 126 {
				return "", "", "", ErrSignature
			}
		}
	}
	if r.Method == "" || strings.ToUpper(r.Method) != r.Method || strings.ContainsAny(r.Method, " \r\n\t") {
		return "", "", "", ErrSignature
	}
	return authority, path, "?" + r.URL.RawQuery, nil
}
func signatureBase(r *http.Request, parameters string) ([]byte, error) {
	authority, path, query, e := target(r)
	if e != nil {
		return nil, e
	}
	var b strings.Builder
	for _, item := range [][2]string{{"@method", r.Method}, {"@scheme", "https"}, {"@authority", authority}, {"@path", path}, {"@query", query}} {
		fmt.Fprintf(&b, "%q: %s\n", item[0], item[1])
	}
	for _, key := range headers[:7] {
		value, e := one(r, key)
		if e != nil {
			return nil, e
		}
		fmt.Fprintf(&b, "%q: %s\n", strings.ToLower(key), value)
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", parameters)
	return []byte(b.String()), nil
}

// Parse 重算实际正文摘要并拒绝重复头、Trailer 和内容编码；只验摘要头签名不能保护正文。
// 此处不依据本机时间授权，创建/到期判断由权威数据库在最终认证事务执行。
func Parse(r *http.Request, body []byte) (Message, error) {
	var m Message
	if len(body) > MaxBody || len(r.Trailer) > 0 || len(r.Header.Values("Trailer")) > 0 || len(r.Header.Values("Content-Encoding")) > 0 {
		return m, ErrSignature
	}
	for _, key := range headers {
		if _, e := one(r, key); e != nil {
			return m, e
		}
	}
	if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Digest") != Digest(body) {
		return m, ErrSignature
	}
	input := r.Header.Get("Signature-Input")
	prefix := "keygate=" + components
	if !strings.HasPrefix(input, prefix) {
		return m, ErrSignature
	}
	values := paramsPattern.FindStringSubmatch(strings.TrimPrefix(input, prefix))
	if len(values) != 6 {
		return m, ErrSignature
	}
	var e error
	m.Created, e = decimal(values[1])
	if e != nil {
		return m, e
	}
	m.Expires, e = decimal(values[2])
	if e != nil || m.Expires <= m.Created || m.Expires-m.Created > 60 || m.Expires > 253402300799 {
		return m, ErrSignature
	}
	nonce, e := base64.RawURLEncoding.DecodeString(values[3])
	if e != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != values[3] {
		return m, ErrSignature
	}
	copy(m.Nonce[:], nonce)
	version, e := decimal(values[5])
	if e != nil || version == 0 {
		return m, ErrSignature
	}
	m.Version = uint64(version)
	m.ClientID = values[4]
	m.Environment = r.Header.Get("X-Keygate-Environment")
	m.Audience = r.Header.Get("X-Keygate-Audience")
	m.RequestID = r.Header.Get("X-Keygate-Request-Id")
	if !id.MatchString(m.Environment) || !id.MatchString(m.Audience) || !id.MatchString(m.RequestID) || r.Header.Get("X-Keygate-Client") != m.ClientID || r.Header.Get("X-Keygate-Key-Version") != values[5] {
		return m, ErrSignature
	}
	signature := r.Header.Get("Signature")
	if !strings.HasPrefix(signature, "keygate=:") || !strings.HasSuffix(signature, ":") {
		return m, ErrSignature
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(signature, "keygate=:"), ":")
	m.MAC, e = base64.StdEncoding.DecodeString(encoded)
	if e != nil || len(m.MAC) != 32 || base64.StdEncoding.EncodeToString(m.MAC) != encoded {
		return m, ErrSignature
	}
	m.Base, e = signatureBase(r, strings.TrimPrefix(input, "keygate="))
	return m, e
}
func (m Message) Verify(key []byte) bool {
	if len(key) != 32 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(m.Base)
	return hmac.Equal(mac.Sum(nil), m.MAC)
}

// Sign 用于可信后端或测试客户端；传入新 nonce，业务重试不能重用签名。
// 此函数不存储秘密，也不会把它写入 Header、日志或 URL。
func Sign(r *http.Request, body, key []byte, m Message) error {
	if len(key) != 32 || !id.MatchString(m.ClientID) || !id.MatchString(m.Environment) || !id.MatchString(m.Audience) || !id.MatchString(m.RequestID) || m.Version == 0 || m.Version > 9007199254740991 || m.Created < 0 || m.Expires <= m.Created || m.Expires-m.Created > 60 {
		return ErrSignature
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Digest", Digest(body))
	r.Header.Set("X-Keygate-Client", m.ClientID)
	r.Header.Set("X-Keygate-Key-Version", strconv.FormatUint(m.Version, 10))
	r.Header.Set("X-Keygate-Audience", m.Audience)
	r.Header.Set("X-Keygate-Environment", m.Environment)
	r.Header.Set("X-Keygate-Request-Id", m.RequestID)
	parameters := fmt.Sprintf(`%s;created=%d;expires=%d;nonce="%s";keyid="%s/%d";alg="hmac-sha256";tag="ex-keygate-auth-v1"`, components, m.Created, m.Expires, base64.RawURLEncoding.EncodeToString(m.Nonce[:]), m.ClientID, m.Version)
	r.Header.Set("Signature-Input", "keygate="+parameters)
	base, e := signatureBase(r, parameters)
	if e != nil {
		return e
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(base)
	r.Header.Set("Signature", "keygate=:"+base64.StdEncoding.EncodeToString(mac.Sum(nil))+":")
	return nil
}
