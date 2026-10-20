package webauth

import (
	"context"
	"errors"
	"ex-keygate/internal/storage"
	"net/http"
	"time"
)

func (s *Service) approvalNotificationRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /api/notifications", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.ApprovalNotifications(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
	handle("POST /api/notifications/{id}/read", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var body struct{}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		if e := s.flow.control.ReadApprovalNotification(r.Context(), token, r.PathValue("id")); e != nil {
			s.businessError(w, r, e)
			return
		}
		w.WriteHeader(204)
	})
	handle("POST /api/requests/{id}/withdraw", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, true)
		if !ok {
			return
		}
		var body struct {
			Digest string `json:"digest"`
			Reason string `json:"reason"`
		}
		if e := strictJSON(w, r, &body); e != nil {
			s.businessError(w, r, e)
			return
		}
		out, e := s.flow.control.WithdrawRequest(r.Context(), token, r.PathValue("id"), body.Digest, body.Reason, requestID(r))
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, out)
	})
}

// RunApprovalNotifications 将数据库扫描与外部投递分开，慢插件不阻断超时判断或任何审批事务。
func (s *Service) RunApprovalNotifications(ctx context.Context, plugin storage.ApprovalNotificationPlugin) {
	if s.flow == nil {
		return
	}
	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		if plugin == nil {
			return
		}
		failed := false
		for {
			if ctx.Err() != nil {
				return
			}
			job, cancel := context.WithTimeout(ctx, 12*time.Second)
			worked, e := s.flow.control.DispatchApprovalNotification(job, plugin)
			cancel()
			if e != nil && ctx.Err() == nil && !failed {
				s.logger.WarnContext(ctx, "审批通知任务处理失败，保留权威队列等待重试", "environment", s.flow.environment, "result", "failed")
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
	}()
	defer func() { <-dispatchDone }()
	scanFailed := false
	scan := func() {
		job, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		e := s.flow.control.CollectApprovalNotifications(job)
		if e != nil && !errors.Is(e, context.Canceled) && ctx.Err() == nil && !scanFailed {
			s.logger.WarnContext(ctx, "审批通知扫描失败，申请仍按数据库期限拒绝", "environment", s.flow.environment, "result", "failed")
		}
		scanFailed = e != nil
	}
	scan()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}
