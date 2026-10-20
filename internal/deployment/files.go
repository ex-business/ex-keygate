// Package deployment implements development-only encrypted deployment material, never plaintext root export.
package deployment

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ex-keygate/internal/auditarchive"
	"ex-keygate/provider"
)

var ErrState = errors.New("持久部署配置或受保护材料不可用")
var labelName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,255}$`)
var name = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Settings struct {
	Port           int    `json:"port"`
	DatabaseFile   string `json:"databaseFile"`
	SSOFile        string `json:"ssoFile"`
	SSOSecretFile  string `json:"ssoSecretFile"`
	TLSDirectory   string `json:"tlsDirectory"`
	PluginFile     string `json:"pluginFile"`
	MFAPluginsFile string `json:"mfaPluginsFile"`
	TrustDirectory string `json:"trustDirectory"`
	ReminderFile   string `json:"reminderFile"`
	Output         string `json:"output"`
}
type Index struct {
	Format           string `json:"format"`
	Environment      string `json:"environment"`
	ID               string `json:"id"`
	LoginRootID      string `json:"loginRootId"`
	LoginKey         []byte `json:"loginKey"`
	UpgradePublicKey []byte `json:"upgradePublicKey"`
	InitialRootID    string `json:"initialRootId"`
	DatabaseFile     string `json:"databaseFile"`
}
type Revision struct {
	Number       uint64            `json:"number"`
	Protocol     int               `json:"protocol"`
	Schema       int               `json:"schema"`
	Binary       string            `json:"binary"`
	Settings     Settings          `json:"settings"`
	Dependencies map[string]string `json:"dependencies"`
}

func (r Revision) Digest() string {
	raw, _ := json.Marshal(r)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

type Files struct {
	directory     string
	key           []byte
	syncDirectory func(string) error
}

// Open 只接受目录外提供的独立包装密钥；丢失或错误时拒绝，不生成替代根或重开初始化。
func Open(directory, keyFile string, create bool) (*Files, error) {
	directory, e := filepath.Abs(directory)
	if e != nil {
		return nil, ErrState
	}
	keyFile, e = filepath.Abs(keyFile)
	if e != nil {
		return nil, ErrState
	}
	// 父目录别名也要解析，不能通过外部符号链接把包装密钥实际放回密文目录。
	resolvedKey, e := filepath.EvalSymlinks(keyFile)
	if e != nil {
		return nil, ErrState
	}
	resolvedParent, e := filepath.EvalSymlinks(filepath.Dir(directory))
	if e != nil {
		return nil, ErrState
	}
	resolvedDirectory := filepath.Join(resolvedParent, filepath.Base(directory))
	if existing, e := filepath.EvalSymlinks(directory); e == nil {
		resolvedDirectory = existing
	}
	relative, e := filepath.Rel(resolvedDirectory, resolvedKey)
	if e != nil || relative == "." || (!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && relative != "..") {
		return nil, ErrState
	}
	key, e := auditarchive.ReadPrivate(keyFile, 32)
	if e != nil || len(key) != 32 {
		return nil, ErrState
	}
	if create {
		if e = os.Mkdir(directory, 0700); e != nil {
			clear(key)
			return nil, ErrState
		}
	}
	stat, e := os.Lstat(directory)
	if e != nil || !stat.IsDir() || stat.Mode().Perm()&0077 != 0 {
		clear(key)
		return nil, ErrState
	}
	return &Files{directory: directory, key: key}, nil
}
func (f *Files) Close() { clear(f.key) }
func (f *Files) aead() (cipher.AEAD, error) {
	b, e := aes.NewCipher(f.key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func (f *Files) read(label string) ([]byte, error) {
	if !labelName.MatchString(label) {
		return nil, ErrState
	}
	raw, e := auditarchive.ReadPrivate(filepath.Join(f.directory, label+".sealed"), 1<<20)
	if e != nil {
		return nil, ErrState
	}
	a, e := f.aead()
	if e != nil || len(raw) < a.NonceSize()+a.Overhead() {
		return nil, ErrState
	}
	out, e := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], []byte("keygate-deployment-v1\x00"+label))
	if e != nil {
		return nil, ErrState
	}
	return out, nil
}

// write 采用独占创建、fsync及目录同步；同名不同内容拒绝，崩溃留下的文件不能静默覆盖。
func (f *Files) write(label string, raw []byte) error {
	if !labelName.MatchString(label) {
		return ErrState
	}
	path := filepath.Join(f.directory, label+".sealed")
	if old, e := f.read(label); e == nil {
		defer clear(old)
		if bytes.Equal(old, raw) {
			return f.syncPublished(label)
		}
		return ErrState
	} else if _, e = os.Lstat(path); !os.IsNotExist(e) {
		return ErrState
	}
	a, e := f.aead()
	if e != nil {
		return ErrState
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	sealed := a.Seal(nonce, nonce, raw, []byte("keygate-deployment-v1\x00"+label))
	// 临时文件先完整落盘，再以不覆盖的硬链接发布，避免半写文件看起来像可用配置。
	temp, e := os.CreateTemp(f.directory, ".pending-")
	if e != nil {
		return e
	}
	defer os.Remove(temp.Name())
	if _, e = temp.Write(sealed); e != nil {
		temp.Close()
		return e
	}
	if e = temp.Sync(); e != nil {
		temp.Close()
		return e
	}
	if e = temp.Close(); e != nil {
		return e
	}
	if e = os.Link(temp.Name(), path); e != nil {
		return e
	}
	dir, e := os.Open(f.directory)
	if e != nil {
		return e
	}
	defer dir.Close()
	if f.syncDirectory != nil {
		return f.syncDirectory(f.directory)
	}
	return dir.Sync()
}
func (f *Files) WriteIndex(i Index) error {
	raw, e := json.Marshal(i)
	if e != nil {
		return e
	}
	defer clear(raw)
	return f.write("index", raw)
}
func (f *Files) ReadIndex() (Index, error) {
	var i Index
	raw, e := f.read("index")
	if e != nil {
		return i, e
	}
	defer clear(raw)
	if provider.DecodeStrict(raw, &i) != nil || i.Format != "keygate-deployment-v1" || !name.MatchString(i.ID) || !name.MatchString(i.Environment) || !name.MatchString(i.LoginRootID) || !name.MatchString(i.InitialRootID) || i.LoginRootID == i.InitialRootID || len(i.LoginKey) != 32 || len(i.UpgradePublicKey) != 32 || !filepath.IsAbs(i.DatabaseFile) {
		return Index{}, ErrState
	}
	return i, nil
}
func (f *Files) WriteRevision(r Revision) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return f.write(fmt.Sprintf("revision-%d-%s", r.Number, r.Digest()), raw)
}
func (f *Files) ReadRevision(n uint64, digest string) (Revision, error) {
	var r Revision
	raw, e := f.read(fmt.Sprintf("revision-%d-%s", n, digest))
	if e != nil {
		return r, e
	}
	if provider.DecodeStrict(raw, &r) != nil || r.Number != n || n == 0 || r.Digest() != digest {
		return Revision{}, ErrState
	}
	return r, nil
}
func (f *Files) WriteRoot(id string, key []byte) error {
	if !name.MatchString(id) || len(key) != 32 {
		return ErrState
	}
	return f.write("root-"+id, key)
}
func (f *Files) ReadRoot(id string) ([]byte, error) {
	if !name.MatchString(id) {
		return nil, ErrState
	}
	raw, e := f.read("root-" + id)
	if e != nil || len(raw) != 32 {
		return nil, ErrState
	}
	return raw, nil
}
func BinaryDigest() (string, error) {
	path, e := os.Executable()
	if e != nil {
		return "", e
	}
	file, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer file.Close()
	h := sha256.New()
	if _, e = io.Copy(h, file); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Dependencies 固定配置文件内容和其JSON中的文件引用，包装密钥与初始密码/MFA计划不写入修订。
func Dependencies(s Settings) (map[string]string, error) {
	deps := map[string]string{}
	var add func(string) error
	add = func(path string) error {
		if path == "" {
			return nil
		}
		if !filepath.IsAbs(path) {
			return ErrState
		}
		if _, ok := deps[path]; ok {
			return nil
		}
		raw, e := auditarchive.ReadPrivate(path, 1<<20)
		if e != nil {
			return ErrState
		}
		defer clear(raw)
		h := sha256.Sum256(raw)
		deps[path] = hex.EncodeToString(h[:])
		var v any
		if json.Unmarshal(raw, &v) == nil {
			var visit func(any) error
			visit = func(v any) error {
				switch x := v.(type) {
				case map[string]any:
					for k, v := range x {
						if path, ok := v.(string); ok && strings.HasSuffix(strings.ToLower(k), "file") {
							if e := add(path); e != nil {
								return e
							}
						} else if e := visit(v); e != nil {
							return e
						}
					}
				case []any:
					for _, v := range x {
						if e := visit(v); e != nil {
							return e
						}
					}
				}
				return nil
			}
			return visit(v)
		}
		return nil
	}
	for _, p := range []string{s.DatabaseFile, s.SSOFile, s.SSOSecretFile, s.PluginFile, s.MFAPluginsFile, s.ReminderFile} {
		if e := add(p); e != nil {
			return nil, e
		}
	}
	if s.TLSDirectory == "" {
		return nil, ErrState
	}
	for _, n := range []string{"cert.pem", "key.pem", "ca.pem"} {
		if e := add(filepath.Join(s.TLSDirectory, n)); e != nil {
			return nil, e
		}
	}
	if s.TrustDirectory != "" {
		for _, d := range strings.Split(s.TrustDirectory, ",") {
			// 快照不能掩盖原目录误放离线根私钥或权限过宽的问题。
			info, e := os.Lstat(d)
			if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
				return nil, ErrState
			}
			if _, e = os.Lstat(filepath.Join(d, "root.key")); !os.IsNotExist(e) {
				return nil, ErrState
			}
			for _, n := range []string{"root.pem", "status.pem", "status.key", "runtime.json"} {
				if e := add(filepath.Join(d, n)); e != nil {
					return nil, e
				}
			}
		}
	}
	return deps, nil
}
func VerifyDependencies(r Revision) error {
	current, e := Dependencies(r.Settings)
	if e != nil {
		return e
	}
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(r.Dependencies)
	if !bytes.Equal(a, b) {
		return ErrState
	}
	return nil
}

// LoadOrCreateRoot 重新使用已落盘但尚未提交的孤立材料；只有数据库审批成功才登记为可用根。
func (f *Files) LoadOrCreateRoot(id string) ([]byte, error) {
	if !name.MatchString(id) {
		return nil, ErrState
	}
	path := filepath.Join(f.directory, "root-"+id+".sealed")
	if _, e := os.Lstat(path); e == nil {
		if e = f.syncPublished("root-" + id); e != nil {
			return nil, e
		}
		return f.ReadRoot(id)
	} else if !os.IsNotExist(e) {
		return nil, ErrState
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return nil, e
	}
	if e := f.WriteRoot(id, key); e != nil {
		clear(key)
		if !errors.Is(e, os.ErrExist) {
			return nil, e
		}
		if e = f.syncPublished("root-" + id); e != nil {
			return nil, e
		}
		return f.ReadRoot(id)
	}
	return key, nil
}

// syncPublished 重用已存在的文件前再次确认文件和父目录持久性；I/O错误不能被成功读取掩盖。
func (f *Files) syncPublished(label string) error {
	if !labelName.MatchString(label) {
		return ErrState
	}
	path := filepath.Join(f.directory, label+".sealed")
	stat, e := os.Lstat(path)
	if e != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 {
		return ErrState
	}
	file, e := os.Open(path)
	if e != nil {
		return e
	}
	defer file.Close()
	after, e := file.Stat()
	if e != nil || !os.SameFile(stat, after) {
		return ErrState
	}
	if e = file.Sync(); e != nil {
		return e
	}
	dir, e := os.Open(f.directory)
	if e != nil {
		return e
	}
	defer dir.Close()
	if f.syncDirectory != nil {
		return f.syncDirectory(f.directory)
	}
	return dir.Sync()
}
