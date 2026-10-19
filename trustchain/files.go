package trustchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"ex-keygate/internal/manifest"
	"io"
	"os"
	"path/filepath"
	"time"
)

// PrivateDirectory 不接受符号链接或共享可写目录；不会修改已有目录的权限来掩盖错误配置。
func PrivateDirectory(path string, create bool) error {
	if create {
		if e := os.MkdirAll(path, 0700); e != nil {
			return e
		}
	}
	i, e := os.Lstat(path)
	if e != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return ErrInvalid
	}
	return nil
}
func ReadFile(path string, private bool) ([]byte, error) { return readBounded(path, private, 65536) }
func readBounded(path string, private bool, limit int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Size() > limit || private && i.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalid
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(i, after) {
		return nil, ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrInvalid
	}
	return b, nil
}
func WriteNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}
func CertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func ReadCertificate(path string) ([]byte, error) {
	b, e := ReadFile(path, false)
	if e != nil {
		return nil, e
	}
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	return p.Bytes, nil
}
func PrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, e := ReadFile(path, true)
	if e != nil {
		return nil, e
	}
	defer clear(b)
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	defer clear(p.Bytes)
	k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, ErrInvalid
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalid
	}
	return key, nil
}

// DecodeJSON 拒绝重复字段、别名及多余字段，签名规范化独立于传输字段顺序。
func DecodeJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := uniqueJSONValue(d, 0); e != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return ErrInvalid
	}
	var raw any
	d = json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&raw) != nil {
		return ErrInvalid
	}
	a, e := manifest.Canonical(raw)
	if e != nil {
		return ErrInvalid
	}
	c, e := manifest.Canonical(v)
	if e != nil || !bytes.Equal(a, c) {
		return ErrInvalid
	}
	return nil
}
func uniqueJSONValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalid
	}
	token, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if e = uniqueJSONValue(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = uniqueJSONValue(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return ErrInvalid
	}
	_, e = d.Token()
	return e
}

type ClientState struct {
	Schema     string           `json:"schema"`
	Pins       Pins             `json:"pins"`
	Revision   uint64           `json:"revision"`
	LastTime   int64            `json:"lastTime"`
	Seen       map[string]int64 `json:"seen"`
	Challenges map[string]int64 `json:"challenges"`
	directory  string
	lock       *os.File
}

// InitializeClient 显式初始化一次；验证路径从不因文件缺失自动创建空水位。
func InitializeClient(directory string, p Pins, now time.Time) error {
	if PrivateDirectory(directory, true) != nil || !ValidID(p.Environment) || !ValidID(p.ServiceID) || !ValidID(p.Audience) || len(p.RecoveryPublicKey) != ed25519.PublicKeySize || p.Epoch != 1 {
		return ErrInvalid
	}
	if _, e := ParseRoot(p.Root, now); e != nil {
		return e
	}
	s := ClientState{Schema: "keygate-client-state-v1", Pins: p, LastTime: now.Unix(), Seen: map[string]int64{}, Challenges: map[string]int64{}}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return WriteNew(filepath.Join(directory, "state.json"), b)
}

// OpenClient 持锁覆盖读取、验证和写入；崩溃遗留锁不会自动抢占，避免两个进程同时回退水位。
func OpenClient(directory string) (*ClientState, error) {
	if PrivateDirectory(directory, false) != nil {
		return nil, ErrInvalid
	}
	lock, e := os.OpenFile(filepath.Join(directory, "state.lock"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, ErrInvalid
	}
	s := &ClientState{directory: directory, lock: lock}
	b, e := readBounded(filepath.Join(directory, "state.json"), true, 2<<20)
	if e == nil {
		e = DecodeJSON(b, s)
	}
	if e != nil || s.Schema != "keygate-client-state-v1" || s.Pins.Epoch == 0 || s.Pins.Epoch > 9007199254740991 || !ValidID(s.Pins.Environment) || !ValidID(s.Pins.ServiceID) || !ValidID(s.Pins.Audience) || len(s.Pins.RecoveryPublicKey) != 32 || s.Seen == nil || s.Challenges == nil || len(s.Seen) > 10000 || len(s.Challenges) > 10000 {
		s.Close()
		return nil, ErrInvalid
	}
	return s, nil
}
func (s *ClientState) Close() {
	if s.lock != nil {
		s.lock.Close()
		os.Remove(filepath.Join(s.directory, "state.lock"))
		s.lock = nil
	}
}
func (s *ClientState) save() error {
	if s.lock == nil {
		return ErrInvalid
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > 2<<20 {
		return ErrInvalid
	}
	f, e := os.CreateTemp(s.directory, ".state-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, filepath.Join(s.directory, "state.json")); e != nil {
		return e
	}
	dir, e := os.Open(s.directory)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *ClientState) clock(now time.Time) error {
	if now.Unix() < s.LastTime {
		return ErrInvalid
	}
	return nil
}
func (s *ClientState) clean(now time.Time) {
	for n, e := range s.Seen {
		if e <= now.Unix() {
			delete(s.Seen, n)
		}
	}
	for n, e := range s.Challenges {
		if e <= now.Unix() {
			delete(s.Challenges, n)
		}
	}
}
func (s *ClientState) Challenge(now time.Time) (string, error) {
	if s.clock(now) != nil {
		return "", ErrInvalid
	}
	s.clean(now)
	if len(s.Challenges) >= 10000 {
		return "", ErrInvalid
	}
	n, e := NewNonce()
	if e != nil {
		return "", e
	}
	s.Challenges[n] = now.Unix() + 60
	s.LastTime = now.Unix()
	if e = s.save(); e != nil {
		return "", e
	}
	return n, nil
}
func (s *ClientState) Accept(environment, service, nonce string, revision uint64, expiry, now time.Time) error {
	if s.clock(now) != nil || s.Pins.Environment != environment || s.Pins.ServiceID != service || revision < s.Revision || s.Challenges[nonce] <= now.Unix() {
		return ErrInvalid
	}
	s.clean(now)
	if _, ok := s.Seen[nonce]; ok {
		return ErrInvalid
	}
	if len(s.Seen) >= 10000 {
		return ErrInvalid
	}
	delete(s.Challenges, nonce)
	s.Seen[nonce] = expiry.Unix()
	s.Revision = revision
	s.LastTime = now.Unix()
	return s.save()
}
func (s *ClientState) Verify(m Message, status Status, nonce string, payload []byte, now time.Time) error {
	if s.clock(now) != nil {
		return ErrInvalid
	}
	return (Verifier{Root: s.Pins.Root, Environment: s.Pins.Environment, ServiceID: s.Pins.ServiceID, Audience: s.Pins.Audience, State: s}).Verify(m, status, nonce, payload, now)
}
func (s *ClientState) Recover(update RecoveryUpdate, now time.Time) error {
	if s.clock(now) != nil {
		return ErrInvalid
	}
	pins, e := ApplyRecovery(s.Pins, update, now)
	if e != nil {
		return e
	}
	s.Pins = pins
	s.Revision = 0
	s.Challenges = map[string]int64{}
	s.LastTime = now.Unix()
	return s.save()
}
