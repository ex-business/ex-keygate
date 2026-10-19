package webauth

import (
	"context"
	"net/http"
	"time"
)

type requestIDKey struct{}

func requestID(r *http.Request) string {
	value, _ := r.Context().Value(requestIDKey{}).(string)
	return value
}

// Never log upstream error bodies, query strings, cookies, tokens or verifier
// material. Log one representative rejection per five seconds per instance.
// Suppression is observational only and is never used to make an auth decision.
func (s *Service) rejected(r *http.Request, stage, reason, target string) {
	now := time.Now().UnixNano()
	last := s.lastRejection.Load()
	if now-last < int64(5*time.Second) || !s.lastRejection.CompareAndSwap(last, now) {
		s.suppressed.Add(1)
		return
	}
	s.logger.WarnContext(r.Context(), "登录或会话处理被拒绝", "request_id", requestID(r), "stage", stage, "reason", reason, "target_id", target, "result", "rejected", "suppressed_count", s.suppressed.Swap(0))
}
func (s *Service) completed(ctx context.Context, id, principal, target, action string) {
	s.logger.InfoContext(ctx, "身份会话操作完成", "request_id", id, "principal_id", principal, "target_id", target, "action", action, "result", "success")
}
