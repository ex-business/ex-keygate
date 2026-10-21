// Package alertmock 仅模拟邮件、短信和Webhook接收，不向外部发送消息。
package alertmock

import (
	"crypto/sha256"
	"encoding/json"
	"ex-keygate/internal/access"
	"io"
	"net/http"
	"sync"
	"time"
)

type Service struct {
	mu       sync.Mutex
	failures int
	entries  map[string]*entry
}
type entry struct {
	digest   [32]byte
	attempts int
	accepted bool
}

func New(failures int) *Service { return &Service{failures: failures, entries: map[string]*entry{}} }
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			w.WriteHeader(400)
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		if e != nil {
			w.WriteHeader(400)
			return
		}
		var v struct {
			ID         string    `json:"id"`
			IncidentID string    `json:"incidentId"`
			EventID    string    `json:"eventId"`
			RouteID    string    `json:"routeId"`
			Channel    string    `json:"channel"`
			Target     string    `json:"target"`
			Kind       string    `json:"kind"`
			Code       string    `json:"code"`
			NodeID     string    `json:"nodeId"`
			ObservedAt time.Time `json:"observedAt"`
			Path       string    `json:"path"`
		}
		if json.Unmarshal(raw, &v) != nil || !access.ValidID(v.ID) || r.Header.Get("Idempotency-Key") != v.ID || !access.ValidID(v.Target) || (v.Channel != "email" && v.Channel != "sms" && v.Channel != "webhook") || v.Path != "/manage#monitoring" {
			w.WriteHeader(400)
			return
		}
		digest := sha256.Sum256(raw)
		s.mu.Lock()
		defer s.mu.Unlock()
		item := s.entries[v.ID]
		if item == nil {
			if len(s.entries) >= 10000 {
				w.WriteHeader(503)
				return
			}
			item = &entry{digest: digest}
			s.entries[v.ID] = item
		}
		if item.digest != digest {
			w.WriteHeader(409)
			return
		}
		item.attempts++
		if !item.accepted && item.attempts <= s.failures {
			w.WriteHeader(503)
			return
		}
		item.accepted = true
		w.WriteHeader(204)
	})
	return mux
}
