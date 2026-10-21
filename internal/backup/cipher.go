package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const chunkSize = 1 << 20

var magic = []byte("KEYGATE-BACKUP-1\n")
var ErrBackup = errors.New("备份或恢复校验失败")

func fileAEAD(key, salt []byte) (cipher.AEAD, error) {
	if len(key) != 32 || len(salt) != 32 {
		return nil, ErrBackup
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("keygate-backup-file-key-v1"))
	h.Write(salt)
	derived := h.Sum(nil)
	defer clear(derived)
	block, e := aes.NewCipher(derived)
	if e != nil {
		return nil, ErrBackup
	}
	return cipher.NewGCM(block)
}
func nonce(index uint64) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out[4:], index)
	return out
}
func aad(index uint64, size uint32) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out, index)
	binary.BigEndian.PutUint32(out[8:], size)
	return out
}
func writeAll(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

// 每文件随机256位salt派生独立密钥，计数nonce不重用；零长度终块认证完整流，截断、重排和尾部追加均拒绝。
func encrypt(w io.Writer, r io.Reader, key []byte) error {
	salt := make([]byte, 32)
	if _, e := rand.Read(salt); e != nil {
		return e
	}
	a, e := fileAEAD(key, salt)
	if e != nil {
		return e
	}
	if e = writeAll(w, append(append([]byte{}, magic...), salt...)); e != nil {
		return e
	}
	buf := make([]byte, chunkSize)
	defer clear(buf)
	for index := uint64(0); ; index++ {
		n, re := io.ReadFull(r, buf)
		if re != nil && re != io.EOF && re != io.ErrUnexpectedEOF {
			return re
		}
		size := uint32(n)
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, size)
		if e = writeAll(w, header); e != nil {
			return e
		}
		sealed := a.Seal(nil, nonce(index), buf[:n], aad(index, size))
		if e = writeAll(w, sealed); e != nil {
			return e
		}
		if n == 0 {
			return nil
		}
	}
}
func decrypt(w io.Writer, r io.Reader, key []byte) error {
	header := make([]byte, len(magic)+32)
	if _, e := io.ReadFull(r, header); e != nil || !hmac.Equal(header[:len(magic)], magic) {
		return ErrBackup
	}
	a, e := fileAEAD(key, header[len(magic):])
	if e != nil {
		return e
	}
	for index := uint64(0); ; index++ {
		sizeRaw := make([]byte, 4)
		if _, e = io.ReadFull(r, sizeRaw); e != nil {
			return ErrBackup
		}
		size := binary.BigEndian.Uint32(sizeRaw)
		if size > chunkSize {
			return ErrBackup
		}
		sealed := make([]byte, int(size)+a.Overhead())
		if _, e = io.ReadFull(r, sealed); e != nil {
			return ErrBackup
		}
		plain, e := a.Open(nil, nonce(index), sealed, aad(index, size))
		if e != nil {
			return ErrBackup
		}
		if size == 0 {
			var tail [1]byte
			n, e := r.Read(tail[:])
			if n != 0 || e != io.EOF {
				return ErrBackup
			}
			return nil
		}
		e = writeAll(w, plain)
		clear(plain)
		if e != nil {
			return e
		}
	}
}
