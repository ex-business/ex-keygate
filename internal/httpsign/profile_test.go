package httpsign

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func vector(t *testing.T) (*http.Request, []byte, []byte, string) {
	t.Helper()
	raw, e := os.ReadFile("testdata/vector.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		URL, Method, Body, PublicTestKey, Base string
		Headers                                map[string]string
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	r, e := http.NewRequest(v.Method, v.URL, strings.NewReader(v.Body))
	if e != nil {
		t.Fatal(e)
	}
	for k, value := range v.Headers {
		r.Header.Set(k, value)
	}
	key, e := base64.StdEncoding.DecodeString(v.PublicTestKey)
	if e != nil {
		t.Fatal(e)
	}
	return r, []byte(v.Body), key, v.Base
}
func TestPythonVector(t *testing.T) {
	r, body, key, base := vector(t)
	m, e := Parse(r, body)
	if e != nil || string(m.Base) != base || !m.Verify(key) {
		t.Fatal("independent vector failed", e)
	}
	signature := r.Header.Get("Signature")
	if e = Sign(r, body, key, m); e != nil || r.Header.Get("Signature") != signature {
		t.Fatal("signer differs from independent vector", e)
	}
}
func TestMessageTamperingAndStrictProfile(t *testing.T) {
	for _, scenario := range []string{"body", "method", "path", "query", "host", "client", "version", "audience", "environment", "request", "nonce", "duplicate", "algorithm", "tag", "trailer", "encoding", "digest", "extra-signature"} {
		t.Run(scenario, func(t *testing.T) {
			r, body, key, _ := vector(t)
			switch scenario {
			case "body":
				body = []byte(`{"probe":false}`)
			case "method":
				r.Method = "PUT"
			case "path":
				r.URL.RawPath = "/a%2fb"
			case "query":
				r.URL.RawQuery = "x=2&x=1&z=%2F"
			case "host":
				r.Host = "other.example"
			case "client":
				r.Header.Set("X-Keygate-Client", "other")
			case "version":
				r.Header.Set("X-Keygate-Key-Version", "2")
			case "audience":
				r.Header.Set("X-Keygate-Audience", "other")
			case "environment":
				r.Header.Set("X-Keygate-Environment", "other")
			case "request":
				r.Header.Set("X-Keygate-Request-Id", "other")
			case "nonce":
				r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), "ICEiIyQl", "AAAAAAAA", 1))
			case "duplicate":
				r.Header.Add("X-Keygate-Client", "backend")
			case "algorithm":
				r.Header.Set("Signature-Input", strings.ReplaceAll(r.Header.Get("Signature-Input"), "hmac-sha256", "rsa-v1"))
			case "tag":
				r.Header.Set("Signature-Input", strings.ReplaceAll(r.Header.Get("Signature-Input"), "ex-keygate-auth-v1", "enrollment"))
			case "trailer":
				r.Trailer = http.Header{"X-Other": []string{"x"}}
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "digest":
				r.Header.Set("Content-Digest", Digest([]byte("different")))
			case "extra-signature":
				r.Header.Add("Signature", r.Header.Get("Signature"))
			}
			m, e := Parse(r, body)
			if e == nil && m.Verify(key) {
				t.Fatal("tampered message accepted")
			}
		})
	}
}
