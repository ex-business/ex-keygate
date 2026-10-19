// Package auditarchive 提供受控运维使用的本地签名归档，生产可替换为独立不可变存储。
package auditarchive

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"ex-keygate/internal/access"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var ErrIntegrity = errors.New("归档完整性校验失败")

type Signed struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}
type Files struct {
	Dir string
	Key ed25519.PrivateKey
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func privateDir(dir string) error {
	info, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ErrIntegrity
	}
	return nil
}
func ReadPrivate(path string, max int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, ErrIntegrity
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Size() > max {
		return nil, ErrIntegrity
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) > max || !os.SameFile(info, after) || after.Mode().Perm()&0077 != 0 || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, ErrIntegrity
	}
	return raw, nil
}

// WriteOnce 用完整临时文件和排他硬链接发布，避免崩溃留下半个正式归档；同名内容必须完全一致。
func WriteOnce(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if e := privateDir(dir); e != nil {
		return e
	}
	tmp, e := os.CreateTemp(dir, ".pending-")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(raw); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Sync(); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	if e = os.Link(name, path); e != nil {
		if !errors.Is(e, os.ErrExist) {
			return e
		}
		existing, readErr := ReadPrivate(path, 16<<20)
		if readErr != nil {
			return readErr
		}
		if string(existing) != string(raw) {
			return ErrIntegrity
		}
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (f Files) Put(ctx context.Context, id string, raw []byte) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if !access.ValidID(id) || len(f.Key) != ed25519.PrivateKeySize || len(raw) > 1<<20 {
		return "", ErrIntegrity
	}
	var event struct {
		EventID string `json:"eventId"`
	}
	if json.Unmarshal(raw, &event) != nil || event.EventID != id {
		return "", ErrIntegrity
	}
	envelope, e := json.Marshal(Signed{raw, ed25519.Sign(f.Key, raw)})
	if e != nil {
		return "", e
	}
	if e = WriteOnce(filepath.Join(f.Dir, id+".json"), envelope); e != nil {
		return "", e
	}
	return digest(raw), nil
}

type Inventory struct {
	Version     string `json:"version"`
	Environment string `json:"environment"`
	Count       int    `json:"count"`
	Digest      string `json:"digest"`
}

// VerifyInventory 遍历时验签；文件集合摘要必须另存可信校验点，不能用同一目录内自报 hash 证明未删档。
func VerifyInventory(dir, environment string, pub ed25519.PublicKey, visit func([]byte) error) (Inventory, error) {
	out := Inventory{Version: "keygate-archive-v1", Environment: environment}
	if !access.ValidID(environment) || len(pub) != ed25519.PublicKeySize {
		return out, ErrIntegrity
	}
	if e := privateDir(dir); e != nil {
		return out, e
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return out, e
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	h := sha256.New()
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pending-") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") || !access.ValidID(strings.TrimSuffix(entry.Name(), ".json")) {
			return out, ErrIntegrity
		}
		raw, e := ReadPrivate(filepath.Join(dir, entry.Name()), 2<<20)
		if e != nil {
			return out, e
		}
		var signed Signed
		if json.Unmarshal(raw, &signed) != nil || !ed25519.Verify(pub, signed.Payload, signed.Signature) {
			return out, ErrIntegrity
		}
		var event struct {
			EventID     string `json:"eventId"`
			Environment string `json:"environment"`
		}
		if json.Unmarshal(signed.Payload, &event) != nil || event.EventID+".json" != entry.Name() || event.Environment != environment {
			return out, ErrIntegrity
		}
		if visit != nil {
			if e = visit(signed.Payload); e != nil {
				return out, e
			}
		}
		_, _ = h.Write([]byte(entry.Name() + ":" + digest(signed.Payload) + "\n"))
		out.Count++
	}
	out.Digest = hex.EncodeToString(h.Sum(nil))
	return out, nil
}

// VerifySignedFile 只验证固定外部公钥签名，不从文件自带字段认领信任；业务调用者再校验 payload 类型与作用域。
func VerifySignedFile(path string, pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrIntegrity
	}
	raw, e := ReadPrivate(path, 1<<20)
	if e != nil {
		return nil, e
	}
	var signed Signed
	if json.Unmarshal(raw, &signed) != nil || !ed25519.Verify(pub, signed.Payload, signed.Signature) {
		return nil, ErrIntegrity
	}
	return signed.Payload, nil
}
