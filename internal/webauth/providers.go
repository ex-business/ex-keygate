package webauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"ex-keygate/internal/auditarchive"
	"ex-keygate/internal/storage"
	"ex-keygate/provider"
	"net/http"
	"net/netip"
)

type pluginRuntime struct {
	binding        provider.Binding
	remote         *provider.HTTPVerifier
	payload, proof []byte
}
type pluginFile struct {
	DevelopmentOnly bool                `json:"developmentOnly"`
	Descriptor      provider.Descriptor `json:"descriptor"`
	Endpoint        string              `json:"endpoint"`
	AllowedIPs      []string            `json:"allowedIPs"`
	CAFile          string              `json:"caFile"`
	ClientCertFile  string              `json:"clientCertFile"`
	ClientKeyFile   string              `json:"clientKeyFile"`
	Payload         []byte              `json:"payload"`
	Proof           []byte              `json:"proof"`
}

// ConfigureDevelopmentPlugins 只在监听前装配受信启动配置；浏览器不能提交地址、证书或私钥。
// 公开配置摘要绑定审批，私钥不入库；本入口仅供开发模拟，不授权真实第三方客户端认证。
func (s *Service) ConfigureDevelopmentPlugins(ctx context.Context, path string) error {
	f := s.flow
	if f == nil || !s.config.Identity.DevelopmentMode {
		return ErrConfig
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed || f.plugins != nil {
		return ErrConfig
	}
	entries := map[string]*pluginRuntime{}
	for _, b := range []provider.Binding{provider.InternalBinding(), provider.HardwareBinding()} {
		entries[b.Descriptor.ID] = &pluginRuntime{binding: b}
	}
	if path != "" {
		raw, e := auditarchive.ReadPrivate(path, 16<<10)
		if e != nil {
			return ErrConfig
		}
		var cfg pluginFile
		if provider.DecodeStrict(raw, &cfg) != nil || !cfg.DevelopmentOnly || cfg.Descriptor.ID == "internal-software" || cfg.Descriptor.ID == "hardware-reserved" {
			return ErrConfig
		}
		ca, e := auditarchive.ReadPrivate(cfg.CAFile, 64<<10)
		if e != nil {
			return ErrConfig
		}
		cert, e := auditarchive.ReadPrivate(cfg.ClientCertFile, 64<<10)
		if e != nil {
			return ErrConfig
		}
		key, e := auditarchive.ReadPrivate(cfg.ClientKeyFile, 64<<10)
		if e != nil {
			return ErrConfig
		}
		defer clear(key)
		pair, e := tls.X509KeyPair(cert, key)
		if e != nil {
			return ErrConfig
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return ErrConfig
		}
		ips := []netip.Addr{}
		for _, ip := range cfg.AllowedIPs {
			a, e := netip.ParseAddr(ip)
			if e != nil {
				return ErrConfig
			}
			ips = append(ips, a)
		}
		adapter, e := provider.NewHTTPVerifier(provider.HTTPConfig{Descriptor: cfg.Descriptor, Endpoint: cfg.Endpoint, AllowedIPs: ips, Roots: roots, Certificate: pair})
		if e != nil {
			return ErrConfig
		}
		// 摘要只包含公开信息，并覆盖自检向量；更换信任、客户端证书或目标必须重新审批。
		public, _ := json.Marshal(struct {
			Descriptor     provider.Descriptor
			Endpoint       string
			IPs            []string
			CA, Cert       string
			Payload, Proof []byte
		}{cfg.Descriptor, cfg.Endpoint, cfg.AllowedIPs, provider.Hash(ca), provider.Hash(cert), cfg.Payload, cfg.Proof})
		b := provider.Binding{Schema: "keygate-plugin-binding-v1", Descriptor: cfg.Descriptor, Executor: "https_mtls", ConfigurationHash: provider.Hash(public)}
		if len(cfg.Payload) == 0 || len(cfg.Payload) > 64<<10 || len(cfg.Proof) == 0 || len(cfg.Proof) > 512 {
			adapter.Close()
			return ErrConfig
		}
		entries[b.Descriptor.ID] = &pluginRuntime{binding: b, remote: adapter, payload: cfg.Payload, proof: cfg.Proof}
	}
	for _, entry := range entries {
		if e := f.control.RegisterProviderOffline(ctx, entry.binding, "plugin-register-"+hexToken()); e != nil {
			for _, p := range entries {
				if p.remote != nil {
					p.remote.Close()
				}
			}
			return e
		}
	}
	f.plugins = entries
	return nil
}

func (s *Service) ClosePlugins() {
	if s.flow == nil {
		return
	}
	s.flow.mu.Lock()
	defer s.flow.mu.Unlock()
	for _, p := range s.flow.plugins {
		if p.remote != nil {
			p.remote.Close()
		}
	}
}

type pluginView struct {
	Policy          storage.ProviderPolicy `json:"policy"`
	InstalledDigest string                 `json:"installedDigest,omitempty"`
	Executor        string                 `json:"executor,omitempty"`
	Check           *storage.ProviderCheck `json:"check,omitempty"`
}

func (s *Service) providerRoutes(handle func(string, http.HandlerFunc)) {
	f := s.flow
	handle("GET /api/providers", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		policies, e := f.control.Providers(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		checks, e := f.control.ProviderChecks(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		out := []pluginView{}
		for _, policy := range policies {
			v := pluginView{Policy: policy}
			if p := f.plugins[policy.ID]; p != nil {
				_, v.InstalledDigest, _ = p.binding.Encode()
				v.Executor = p.binding.Executor
			}
			if c, ok := checks[policy.ID]; ok {
				v.Check = &c
			}
			out = append(out, v)
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/providers/{provider}/disable", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var body struct{}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		if e := f.control.DisableProvider(r.Context(), token, r.PathValue("provider"), requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, map[string]bool{"disabled": true})
	})
	handle("POST /api/providers/{provider}/check", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var body struct{}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		p := f.plugins[r.PathValue("provider")]
		if p == nil || p.binding.Executor == "reserved" {
			s.businessError(w, r, storage.ErrInvalid)
			return
		}
		_, digest, _ := p.binding.Encode()
		out, e := f.control.CheckProvider(r.Context(), token, p.binding.Descriptor.ID, digest, requestID(r), func(ctx context.Context) (bool, error) {
			if p.remote != nil {
				if e := p.remote.CheckHealth(ctx); e != nil {
					return false, e
				}
				e := p.remote.Verify(ctx, provider.Verification{Environment: f.environment, Audience: "keygate-plugin-selftest", Purpose: "conformance", RequestID: requestID(r), ClientID: "plugin-diagnostic", Key: provider.KeyReference{ID: "mock-conformance", Version: 1}, Algorithm: "ed25519", Payload: p.payload, Proof: p.proof})
				return e == nil, e
			}
			roots, _ := f.keySnapshot()
			if len(roots) == 0 {
				return false, provider.ErrUnavailable
			}
			for _, k := range roots {
				if e := k.CheckHealth(ctx); e != nil {
					return false, e
				}
			}
			return false, nil
		})
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
}
