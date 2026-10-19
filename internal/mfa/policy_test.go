package mfa

import (
	"strings"
	"testing"
	"time"
)

func TestCombinationDoesNotCountRepeatedProofs(t *testing.T) {
	policy := Policy{M: 2, Rules: []Rule{{Email, 1, 1, false}, {TOTP, 1, 1, true}, {Hardware, 1, 1, false}}}
	factors := []Factor{{ID: "mail", Method: Email, Label: "邮件", Reference: "one@example.invalid", Fingerprint: strings.Repeat("a", 64)}, {ID: "otp", Method: TOTP, Label: "动态码", SecretCipher: []byte("protected"), Fingerprint: strings.Repeat("b", 64)}, {ID: "key", Method: Hardware, Label: "硬件", Reference: "key-1", Fingerprint: strings.Repeat("c", 64)}}
	if policy.Satisfied(factors, []string{"mail", "mail", "unknown"}) {
		t.Fatal("同项重复占票")
	}
	if policy.Satisfied(factors, []string{"mail", "key"}) {
		t.Fatal("绕过必需TOTP")
	}
	if !policy.Satisfied(factors, []string{"mail", "otp"}) {
		t.Fatal("合法组合被拒绝")
	}
}
func TestRFC6238AndReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		at   int64
		code string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := totp(secret, tc.at/30, 8); got != tc.code {
			t.Fatal("RFC6238向量不一致", tc.at, got)
		}
	}
	now := time.Unix(1234567890, 0)
	code := totp(secret, now.Unix()/30, 6)
	counter, e := TOTPCounter(secret, code, now, -1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = TOTPCounter(secret, code, now, counter); e == nil {
		t.Fatal("动态码可重放")
	}
	if _, e = TOTPCounter(secret, code, now.Add(90*time.Second), -1); e == nil {
		t.Fatal("过期动态码通过")
	}
}
