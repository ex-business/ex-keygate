// Package mfa 定义本机二次验证策略及插件边界，不把验证通过等同于管理授权或多人审批。
package mfa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

type Method string

const (
	Email    Method = "email"
	SMS      Method = "sms"
	TOTP     Method = "totp"
	Hardware Method = "hardware"
)

var ErrInvalid = errors.New("invalid MFA policy or proof")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func (m Method) Valid() bool { return m == Email || m == SMS || m == TOTP || m == Hardware }

type Rule struct {
	Method   Method `json:"method"`
	M        int    `json:"m"`
	N        int    `json:"n"`
	Required bool   `json:"required"`
}
type Policy struct {
	M     int    `json:"m"`
	Rules []Rule `json:"rules"`
}

func (p Policy) Validate() error {
	if len(p.Rules) == 0 || len(p.Rules) > 4 || p.M < 1 || p.M > len(p.Rules) {
		return ErrInvalid
	}
	seen := map[Method]bool{}
	for _, r := range p.Rules {
		if !r.Method.Valid() || seen[r.Method] || r.M < 1 || r.N < r.M || r.N > 16 {
			return ErrInvalid
		}
		seen[r.Method] = true
	}
	return nil
}
func (p Policy) Digest() string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Factor struct {
	ID           string `json:"id"`
	Method       Method `json:"method"`
	Label        string `json:"label"`
	Reference    string `json:"-"`
	SecretCipher []byte `json:"-"`
	// Fingerprint 由可信绑定端生成，识别重复的收件人、设备或TOTP种子；不能由浏览器自报。
	Fingerprint string `json:"-"`
}

func (f Factor) Validate() error {
	if !identifier.MatchString(f.ID) || !f.Method.Valid() || len(f.Label) == 0 || len(f.Label) > 128 || len(f.Reference) > 2048 || len(f.SecretCipher) > 4096 || len(f.Fingerprint) != 64 {
		return ErrInvalid
	}
	if _, e := hex.DecodeString(f.Fingerprint); e != nil {
		return ErrInvalid
	}
	if f.Method == TOTP {
		if len(f.SecretCipher) == 0 || f.Reference != "" {
			return ErrInvalid
		}
	} else if f.Reference == "" || len(f.SecretCipher) > 0 {
		return ErrInvalid
	}
	return nil
}

// Satisfied 先按唯一绑定项计数，再按通过的方式计数；同一项重复证明、未知ID均不能增加票数。
func (p Policy) Satisfied(factors []Factor, verified []string) bool {
	if p.Validate() != nil {
		return false
	}
	byID := map[string]Method{}
	counts := map[Method]int{}
	total := map[Method]int{}
	for _, f := range factors {
		if f.Validate() != nil || byID[f.ID] != "" {
			return false
		}
		byID[f.ID] = f.Method
		total[f.Method]++
	}
	seen := map[string]bool{}
	for _, id := range verified {
		if !seen[id] && byID[id] != "" {
			counts[byID[id]]++
			seen[id] = true
		}
	}
	passed := 0
	for _, r := range p.Rules {
		// N 是显式绑定数量，缺失或新增绑定均需更新策略，不能默默改变分母。
		ok := total[r.Method] == r.N && counts[r.Method] >= r.M
		if r.Required && !ok {
			return false
		}
		if ok {
			passed++
		}
	}
	return passed >= p.M
}
