package webauth

import (
	"context"
	"crypto/ed25519"
	"ex-keygate/internal/storage"
	"ex-keygate/trustchain"
	"net/http"
	"time"
)

type applicationTrustRuntime struct {
	root, certificate []byte
	key               ed25519.PrivateKey
	environment       string
}

// ConfigureApplicationTrust 仅接收公开根与专用状态密钥，绝不加载离线根私钥或业务服务端私钥。
func (s *Service) ConfigureApplicationTrust(ctx context.Context, environment string, root, certificate []byte, key ed25519.PrivateKey) error {
	if s.handlerStarted.Load() || s.flow == nil {
		return ErrConfig
	}
	fingerprint := trustchain.Fingerprint(root)
	if _, exists := s.applicationTrust[fingerprint]; exists {
		return ErrConfig
	}
	pub, e := trustchain.VerifyCertificate(root, certificate, environment, trustchain.StatusPurpose, "trust-status", 1, time.Now())
	if e != nil || len(key) != ed25519.PrivateKeySize || !pub.Equal(key.Public()) {
		return ErrConfig
	}
	if e = s.flow.control.RegisterApplicationRootOffline(ctx, environment, root, "application-root-"+hexToken()); e != nil {
		return e
	}
	if s.applicationTrust == nil {
		s.applicationTrust = map[string]*applicationTrustRuntime{}
	}
	s.applicationTrust[fingerprint] = &applicationTrustRuntime{append([]byte(nil), root...), append([]byte(nil), certificate...), append(ed25519.PrivateKey(nil), key...), environment}
	return nil
}
func (s *Service) trustRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /api/trust/services", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		if s.applicationTrust == nil {
			fail(w, 404)
			return
		}
		roots, services, e := s.flow.control.TrustServices(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, map[string]any{"roots": roots, "services": services, "developmentOnly": true})
	})
	handle("POST /api/trust/{service}/status", func(w http.ResponseWriter, r *http.Request) {
		if s.applicationTrust == nil {
			fail(w, 404)
			return
		}
		var body struct {
			Nonce    string `json:"nonce"`
			Audience string `json:"audience"`
		}
		if strictJSON(w, r, &body) != nil || !trustchain.ValidNonce(body.Nonce) || !trustchain.ValidID(body.Audience) {
			fail(w, 400)
			return
		}
		out, e := s.flow.control.IssueTrustStatus(r.Context(), r.PathValue("service"), requestID(r), func(root storage.ApplicationRoot, current storage.TrustService, now time.Time) (trustchain.Status, error) {
			runtime := s.applicationTrust[root.Fingerprint]
			if runtime == nil {
				return trustchain.Status{}, ErrConfig
			}
			if root.Fingerprint != trustchain.Fingerprint(runtime.root) || root.Environment != runtime.environment {
				return trustchain.Status{}, ErrConfig
			}
			return trustchain.SignStatus(runtime.root, runtime.certificate, runtime.key, trustchain.Status{Environment: root.Environment, ServiceID: current.ServiceID, Revision: current.Revision, Version: current.Version, CertificateHash: current.CertificateHash, Disabled: current.Disabled, Nonce: body.Nonce, Audience: body.Audience}, now)
		})
		if e != nil {
			s.businessError(w, r, e)
			return
		}

		businessJSON(w, 200, out)
	})
	handle("POST /api/trust/{service}/revoke", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		if s.applicationTrust == nil {
			fail(w, 404)
			return
		}
		var body struct {
			Version uint64 `json:"version"`
			Reason  string `json:"reason"`
		}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		if e := s.flow.control.RevokeTrustService(r.Context(), token, r.PathValue("service"), body.Version, body.Reason, requestID(r)); e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
	})
}
