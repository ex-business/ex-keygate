package webauth

import (
	"context"
	"ex-keygate/internal/storage"
	"net/http"
	"time"
)

func (s *Service) trustRenewalRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /api/trust/status-signers", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.TrustStatusSigners(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		ready := map[string]bool{}
		for _, v := range out {
			runtime := s.applicationTrust[v.RootFingerprint]
			ready[v.RootFingerprint] = runtime != nil && runtime.candidates[v.Info.Fingerprint] != nil
		}
		businessJSON(w, 200, map[string]any{"signers": out, "nodeReady": ready})
	})
	handle("GET /api/trust/reminders", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.TrustReminders(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		more := len(out) > 200
		if more {
			out = out[:200]
		}
		businessJSON(w, 200, map[string]any{"reminders": out, "hasMore": more})
	})
}

// RunTrustReminders 在服务生命周期内定期扫描；未配置插件时保留pending供管理页面查看，绝不伪造发送成功。
func (s *Service) RunTrustReminders(ctx context.Context, plugin storage.TrustReminderPlugin) {
	if s.flow == nil || len(s.applicationTrust) == 0 {
		return
	}
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		task, cancel := context.WithTimeout(ctx, 30*time.Second)
		e := s.flow.control.CollectTrustReminders(task)
		if e == nil && plugin != nil {
			for i := 0; i < 2; i++ {
				sent, err := s.flow.control.DispatchTrustReminder(task, plugin)
				if err != nil {
					e = err
					break
				}
				if !sent {
					break
				}
			}
		}
		cancel()
		if e != nil && ctx.Err() == nil {
			s.logger.WarnContext(ctx, "证书到期扫描或提醒处理失败，下一周期重试", "result", "retry")
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
