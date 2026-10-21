package webauth

import (
	"context"
	"ex-keygate/internal/storage"
	"net/http"
	"time"
)

func (s *Service) ConfigureAlertDelivery(ctx context.Context, bindings map[string]storage.AlertBinding) error {
	if s.handlerStarted.Load() || s.flow == nil {
		return storage.ErrInvalid
	}
	routes := []storage.AlertRoute{}
	for _, b := range bindings {
		if b.Plugin == nil {
			return storage.ErrInvalid
		}
		routes = append(routes, b.Route)
	}
	return s.flow.control.ConfigureAlertRoutes(ctx, routes)
}
func (s *Service) alertDeliveryRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /api/alert-deliveries", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.AlertDeliveries(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/alert-silences", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var body struct {
			Code    string `json:"code"`
			Reason  string `json:"reason"`
			Seconds *int   `json:"seconds"`
		}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		if body.Seconds == nil {
			s.businessError(w, r, storage.ErrInvalid)
			return
		}
		if e := s.flow.control.SetAlertSilence(r.Context(), token, body.Code, body.Reason, requestID(r), *body.Seconds); e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
	})
}

// RunAlertDelivery 扫描和投递分别限时，插件I/O不持域事务；没有外部配置时仍跟踪事故但不伪造投递成功。
func (s *Service) RunAlertDelivery(ctx context.Context, bindings map[string]storage.AlertBinding) {
	if s.flow == nil {
		return
	}
	failed := false
	for ctx.Err() == nil {
		job, cancel := context.WithTimeout(ctx, 3*time.Second)
		e := s.flow.control.CollectAlertDeliveries(job)
		cancel()
		worked := false
		if e == nil && len(bindings) > 0 {
			job, cancel = context.WithTimeout(ctx, 12*time.Second)
			worked, e = s.flow.control.DispatchAlertDelivery(job, bindings)
			cancel()
		}
		if e != nil && !failed && ctx.Err() == nil {
			s.logger.WarnContext(ctx, "告警通知任务失败，保留权威队列等待恢复", "environment", s.flow.environment, "result", "failed")
		}
		if e == nil && failed {
			s.logger.InfoContext(ctx, "告警通知任务恢复", "environment", s.flow.environment, "result", "recovered")
		}
		failed = e != nil
		if worked && e == nil {
			continue
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
