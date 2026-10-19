package mfa

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"ex-keygate/provider"
	"io"
	"net/netip"
	"os"
)

type PluginFiles struct {
	Endpoint        string   `json:"endpoint"`
	AllowedIPs      []string `json:"allowedIPs"`
	CAFile          string   `json:"caFile"`
	CertificateFile string   `json:"certificateFile"`
	PrivateKeyFile  string   `json:"privateKeyFile"`
}
type PluginConfig struct {
	Email    *PluginFiles `json:"email"`
	SMS      *PluginFiles `json:"sms"`
	Hardware *PluginFiles `json:"hardware"`
}

// LoadPlugins 不把私钥或验证码纳入公开摘要；固定源、IP和服务端CA构成节点须一致的验证信任配置。
func LoadPlugins(raw []byte) (Plugins, string, func(), error) {
	var c PluginConfig
	var plugins Plugins
	opened := []*HTTPSPlugin{}
	closeAll := func() {
		for _, p := range opened {
			p.Close()
		}
	}
	var wire struct {
		Email    json.RawMessage `json:"email"`
		SMS      json.RawMessage `json:"sms"`
		Hardware json.RawMessage `json:"hardware"`
	}
	if len(raw) > 16384 || provider.DecodeStrict(raw, &wire) != nil {
		return plugins, "", closeAll, ErrInvalid
	}
	// 可选插件允许null；每个非空配置再按明确字段严格解析，不放宽外层或嵌套重复字段规则。
	for i, item := range []json.RawMessage{wire.Email, wire.SMS, wire.Hardware} {
		if len(item) == 0 || string(item) == "null" {
			continue
		}
		parsed := new(PluginFiles)
		if provider.DecodeStrict(item, parsed) != nil {
			return Plugins{}, "", closeAll, ErrInvalid
		}
		switch i {
		case 0:
			c.Email = parsed
		case 1:
			c.SMS = parsed
		case 2:
			c.Hardware = parsed
		}
	}
	descriptors := []any{}
	for i, item := range []*PluginFiles{c.Email, c.SMS, c.Hardware} {
		if item == nil {
			descriptors = append(descriptors, nil)
			continue
		}
		ca, e := readPluginFile(item.CAFile, false)
		if e != nil {
			closeAll()
			return Plugins{}, "", closeAll, e
		}
		cert, e := readPluginFile(item.CertificateFile, false)
		if e != nil {
			closeAll()
			return Plugins{}, "", closeAll, e
		}
		key, e := readPluginFile(item.PrivateKeyFile, true)
		if e != nil {
			closeAll()
			return Plugins{}, "", closeAll, e
		}
		certificate, e := tls.X509KeyPair(cert, key)
		clear(key)
		if e != nil {
			closeAll()
			return Plugins{}, "", closeAll, ErrInvalid
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			closeAll()
			return Plugins{}, "", closeAll, ErrInvalid
		}
		pins := []netip.Addr{}
		for _, rawIP := range item.AllowedIPs {
			ip, e := netip.ParseAddr(rawIP)
			if e != nil {
				closeAll()
				return Plugins{}, "", closeAll, ErrInvalid
			}
			pins = append(pins, ip)
		}
		p, e := NewHTTPSPlugin(item.Endpoint, roots, certificate, pins)
		if e != nil {
			closeAll()
			return Plugins{}, "", closeAll, e
		}
		opened = append(opened, p)
		switch i {
		case 0:
			plugins.Email = p
		case 1:
			plugins.SMS = p
		case 2:
			plugins.Hardware = p
		}
		descriptors = append(descriptors, struct {
			Endpoint string
			IPs      []string
			CAHash   string
			CertHash string
		}{item.Endpoint, item.AllowedIPs, provider.Hash(ca), provider.Hash(cert)})
	}
	encoded, _ := json.Marshal(descriptors)
	return plugins, provider.Hash(encoded), closeAll, nil
}
func readPluginFile(path string, private bool) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || (private && before.Mode().Perm()&0077 != 0) {
		return nil, ErrInvalid
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	after, e := file.Stat()
	if e != nil || !os.SameFile(before, after) || (private && after.Mode().Perm()&0077 != 0) {
		return nil, ErrInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(file, 65537))
	if e != nil || len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrInvalid
	}
	return raw, nil
}
