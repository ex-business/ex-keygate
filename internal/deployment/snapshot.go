package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"ex-keygate/internal/auditarchive"
)

// Snapshot 从每个已核验文件的同一份字节构建私有装配快照，后续加载器不再重读可被替换的原路径。
// 只复制修订内已绑定的依赖，不包含目录外包装密钥或客户端根；调用方退出时删除临时快照。
func (f *Files) Snapshot(r Revision) (Settings, func(), error) {
	dir, e := os.MkdirTemp(f.directory, ".snapshot-")
	if e != nil {
		return Settings{}, nil, e
	}
	clean := func() { _ = os.RemoveAll(dir) }
	ok := false
	defer func() {
		if !ok {
			clean()
		}
	}()
	paths := map[string]string{}
	payloads := map[string][]byte{}
	defer func() {
		for _, raw := range payloads {
			clear(raw)
		}
	}()
	for path, expected := range r.Dependencies {
		raw, e := auditarchive.ReadPrivate(path, 1<<20)
		if e != nil {
			return Settings{}, nil, ErrState
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != expected {
			clear(raw)
			return Settings{}, nil, ErrState
		}
		payloads[path] = raw
		label := sha256.Sum256([]byte(path))
		paths[path] = filepath.Join(dir, hex.EncodeToString(label[:]))
	}
	for path, raw := range payloads {
		var v any
		if json.Unmarshal(raw, &v) == nil {
			var rewrite func(any) error
			rewrite = func(v any) error {
				switch x := v.(type) {
				case map[string]any:
					for k, value := range x {
						if ref, yes := value.(string); yes && strings.HasSuffix(strings.ToLower(k), "file") && ref != "" {
							mapped, yes := paths[ref]
							if !yes {
								return ErrState
							}
							x[k] = mapped
						} else if e := rewrite(value); e != nil {
							return e
						}
					}
				case []any:
					for _, v := range x {
						if e := rewrite(v); e != nil {
							return e
						}
					}
				}
				return nil
			}
			if e = rewrite(v); e != nil {
				return Settings{}, nil, e
			}
			raw, e = json.Marshal(v)
			if e != nil {
				return Settings{}, nil, e
			}
		}
		if e = os.WriteFile(paths[path], raw, 0600); e != nil {
			return Settings{}, nil, e
		}
	}
	s := r.Settings
	for _, p := range []*string{&s.DatabaseFile, &s.SSOFile, &s.SSOSecretFile, &s.PluginFile, &s.MFAPluginsFile, &s.ReminderFile, &s.ApprovalNotifyFile, &s.AlertNotifyFile} {
		if *p != "" {
			mapped, yes := paths[*p]
			if !yes {
				return Settings{}, nil, ErrState
			}
			*p = mapped
		}
	}
	directory := func(original string, names []string) (string, error) {
		label := sha256.Sum256([]byte(original))
		target := filepath.Join(dir, "directory-"+hex.EncodeToString(label[:]))
		if e := os.Mkdir(target, 0700); e != nil {
			return "", e
		}
		for _, name := range names {
			source, yes := paths[filepath.Join(original, name)]
			if !yes {
				return "", ErrState
			}
			if e := os.Link(source, filepath.Join(target, name)); e != nil {
				return "", e
			}
		}
		return target, nil
	}
	s.TLSDirectory, e = directory(s.TLSDirectory, []string{"cert.pem", "key.pem", "ca.pem"})
	if e != nil {
		return Settings{}, nil, e
	}
	if s.TrustDirectory != "" {
		list := strings.Split(s.TrustDirectory, ",")
		for i, path := range list {
			list[i], e = directory(path, []string{"root.pem", "status.pem", "status.key", "runtime.json"})
			if e != nil {
				return Settings{}, nil, e
			}
		}
		s.TrustDirectory = strings.Join(list, ",")
	}
	ok = true
	return s, clean, nil
}
