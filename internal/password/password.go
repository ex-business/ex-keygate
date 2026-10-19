// Package password 提供固定成本的口令摘要，不保存可还原口令。
package password

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"
)

const prefix = "pbkdf2-sha256$600000$"

var ErrInvalid = errors.New("口令或摘要格式无效")

// Hash 使用独立随机盐和固定成本，禁止由配置降低成本或触发任意高成本计算。
func Hash(value string) (string, error) {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 12 || len(value) > 1024 {
		return "", ErrInvalid
	}
	salt := make([]byte, 32)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	key, e := pbkdf2.Key(sha256.New, value, salt, 600000, 32)
	if e != nil {
		return "", e
	}
	defer clear(key)
	return prefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}
func Parse(encoded string) ([]byte, []byte, error) {
	if !strings.HasPrefix(encoded, prefix) {
		return nil, nil, ErrInvalid
	}
	parts := strings.Split(strings.TrimPrefix(encoded, prefix), "$")
	if len(parts) != 2 {
		return nil, nil, ErrInvalid
	}
	salt, e := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	if e != nil || len(salt) != 32 {
		return nil, nil, ErrInvalid
	}
	key, e := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(key) != 32 {
		return nil, nil, ErrInvalid
	}
	return salt, key, nil
}

// Verify 对不存在的账号也执行同等成本；外部统一返回失败，避免枚举人员。
func Verify(encoded, value string) bool {
	salt, want, e := Parse(encoded)
	valid := e == nil
	if !valid {
		salt = make([]byte, 32)
		want = make([]byte, 32)
	}
	if len(value) > 1024 {
		value = ""
		valid = false
	}
	key, e := pbkdf2.Key(sha256.New, value, salt, 600000, 32)
	defer clear(key)
	return e == nil && subtle.ConstantTimeCompare(key, want) == 1 && valid
}
