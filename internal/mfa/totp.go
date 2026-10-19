package mfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// TOTPCounter 只接受六位数字和相邻一个30秒时间窗；last阻止同一绑定在其他会话或节点重放。
func TOTPCounter(secret []byte, code string, now time.Time, last int64) (int64, error) {
	if len(secret) < 20 || len(code) != 6 || now.Unix() < 30 {
		return 0, ErrInvalid
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, ErrInvalid
		}
	}
	step := now.Unix() / 30
	for _, counter := range []int64{step, step - 1, step + 1} {
		if counter <= last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totp(secret, counter, 6)), []byte(code)) == 1 {
			return counter, nil
		}
	}
	return 0, ErrInvalid
}
func totp(secret []byte, counter int64, digits int) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(counter))
	h := hmac.New(sha1.New, secret)
	h.Write(b[:])
	sum := h.Sum(nil)
	o := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}
