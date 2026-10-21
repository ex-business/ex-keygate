package webauth

import (
	"context"
	"ex-keygate/internal/storage"
	"net/http"
	"sync"
	"time"
)

type runtimeMonitor struct {
	mu                 sync.Mutex
	id                 string
	auth               map[string]storage.AuthMinute
	events             []storage.DatabaseObservation
	dbKnown, dbHealthy bool
	dbChecked          time.Time
	sequence           uint64
	lost               uint64
}
type monitorResponse struct {
	http.ResponseWriter
	status int
}

func (w *monitorResponse) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *monitorResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (w *monitorResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// 只记录固定入口与HTTP结果，不读凭据、账号、IP或请求体；计数完全在内存，不把监控数据库写入认证关键事务。
func (s *Service) observeAuthentication(w http.ResponseWriter, kind string) (http.ResponseWriter, func()) {
	wrapped := &monitorResponse{ResponseWriter: w}
	return wrapped, func() {
		if value := recover(); value != nil {
			s.monitor.record(kind, 500)
			panic(value)
		}
		status := wrapped.status
		if status == 0 {
			status = 500
		}
		s.monitor.record(kind, status)
	}
}
func (m *runtimeMonitor) record(kind string, status int) {
	switch kind {
	case "hmac", "h5", "password", "oidc":
	default:
		return
	}
	now := time.Now().UTC().Truncate(time.Minute)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.auth == nil {
		m.auth = map[string]storage.AuthMinute{}
	}
	for k, v := range m.auth {
		if v.Minute.Before(now.Add(-9*time.Minute)) || v.Minute.After(now) {
			delete(m.auth, k)
		}
	}
	key := now.Format(time.RFC3339) + "/" + kind
	v := m.auth[key]
	v.Minute = now
	v.Kind = kind
	if status >= 500 {
		if v.Errors < 1e9 {
			v.Errors++
		}
	} else if status >= 400 {
		if v.Denied < 1e9 {
			v.Denied++
		}
	} else {
		if v.Success < 1e9 {
			v.Success++
		}
	}
	m.auth[key] = v
}
func (m *runtimeMonitor) databaseObservation(healthy bool) (bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.id == "" {
		m.id = hexToken()
	}
	now := time.Now().UTC()
	changed := m.dbKnown && m.dbHealthy != healthy
	firstFailure := !m.dbKnown && !healthy
	m.dbKnown = true
	m.dbHealthy = healthy
	m.dbChecked = now
	if changed || firstFailure {
		m.sequence++
		if len(m.events) >= 64 {
			m.events = m.events[1:]
			m.lost++
		}
		m.events = append(m.events, storage.DatabaseObservation{ID: "db-" + hexToken(), Healthy: healthy, ObservedAt: now})
	}
	return changed || firstFailure, healthy
}
func (m *runtimeMonitor) snapshot() (string, []storage.AuthMinute, []storage.DatabaseObservation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.id == "" {
		m.id = hexToken()
	}
	now := time.Now().UTC()
	a := []storage.AuthMinute{}
	for k, v := range m.auth {
		if v.Minute.Before(now.Truncate(time.Minute).Add(-9 * time.Minute)) {
			delete(m.auth, k)
			continue
		}
		a = append(a, v)
	}
	return m.id, a, append([]storage.DatabaseObservation(nil), m.events...)
}
func (m *runtimeMonitor) acknowledge(events []storage.DatabaseObservation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(events) == 0 {
		return
	}
	done := map[string]bool{}
	for _, e := range events {
		done[e.ID] = true
	}
	remaining := m.events[:0]
	for _, e := range m.events {
		if !done[e.ID] {
			remaining = append(remaining, e)
		}
	}
	m.events = remaining
}
func (m *runtimeMonitor) status() any {
	m.mu.Lock()
	defer m.mu.Unlock()
	var healthy *bool
	if m.dbKnown {
		v := m.dbHealthy
		healthy = &v
	}
	return struct {
		DatabaseHealthy *bool     `json:"databaseHealthy"`
		CheckedAt       time.Time `json:"checkedAt"`
		LostTransitions uint64    `json:"lostTransitions"`
	}{healthy, m.dbChecked, m.lost}
}

// RunMonitoring 数据库故障用本进程状态和日志告警，恢复后补存转换事件；整批探测限时，不能阻塞请求或续租。
func (s *Service) RunMonitoring(ctx context.Context) {
	if s.flow == nil {
		return
	}
	failed := false
	run := func() {
		ping, cancel := context.WithTimeout(ctx, 2*time.Second)
		e := s.store.MonitorDatabase(ping)
		cancel()
		changed, healthy := s.monitor.databaseObservation(e == nil)
		node, _, _ := s.store.NodeIdentity()
		if changed {
			if healthy {
				s.logger.InfoContext(ctx, "数据库监测恢复", "environment", s.flow.environment, "node_id", node, "result", "recovered")
			} else {
				s.logger.ErrorContext(ctx, "数据库监测异常，认证继续按权威库拒绝", "environment", s.flow.environment, "node_id", node, "reason", "database_unavailable", "result", "unavailable")
			}
		}
		if !healthy {
			return
		}
		job, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		targets, e := s.flow.control.MonitorProviderTargets(job)
		plugins := []storage.PluginObservation{}
		if e == nil {
			plugins = probeMonitorPlugins(job, targets, func(probe context.Context, id string) string {
				if id == "internal-software" {
					if s.checkBusinessReadiness(probe) == nil {
						return "ready"
					}
				} else if v := s.flow.plugins[id]; v != nil {
					if v.binding.Executor == "reserved" {
						return "reserved"
					}
					if v.remote != nil && v.remote.CheckHealth(probe) == nil {
						return "ready"
					}
				}
				return "unavailable"
			})
		}
		cancel()
		job, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if e == nil {
			process, auth, events := s.monitor.snapshot()
			e = s.flow.control.SaveMonitorSample(job, process, node, auth, plugins, events)
			if e == nil {
				s.monitor.acknowledge(events)
			}
		}
		if e == nil {
			var alerts []storage.SystemAlert
			alerts, e = s.flow.control.CollectSystemAlerts(job)
			if e == nil {
				for _, a := range alerts {
					if a.Active {
						s.logger.WarnContext(ctx, "系统监控告警触发", "environment", s.flow.environment, "node_id", node, "alert_code", a.Code, "count", a.Count, "severity", a.Severity, "result", "active")
					} else {
						s.logger.InfoContext(ctx, "系统监控告警恢复", "environment", s.flow.environment, "node_id", node, "alert_code", a.Code, "result", "cleared")
					}
				}
			}
		}
		if e != nil && !failed && ctx.Err() == nil {
			s.logger.WarnContext(ctx, "系统监控采集失败，页面数据可能陈旧", "environment", s.flow.environment, "node_id", node, "reason", "collection_or_fencing_failed", "result", "unavailable")
		}
		failed = e != nil
	}
	run()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
func (s *Service) systemMonitorRoutes(handle func(string, http.HandlerFunc)) {
	handle("GET /api/monitoring", func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.businessSession(w, r, false)
		if !ok {
			return
		}
		out, e := s.flow.control.SystemMonitor(r.Context(), token)
		if e != nil {
			s.businessError(w, r, e)
			return
		}
		businessJSON(w, 200, map[string]any{"snapshot": out, "collector": s.monitor.status()})
	})
}

// 探测并发设硬上限；预算耗尽仅代表未知，不能把未执行的检查判为插件故障。
func probeMonitorPlugins(ctx context.Context, ids []string, check func(context.Context, string) string) []storage.PluginObservation {
	out := make([]storage.PluginObservation, len(ids))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				p := storage.PluginObservation{ID: ids[i], State: "unknown"}
				if ctx.Err() == nil {
					probe, cancel := context.WithTimeout(ctx, time.Second)
					p.CheckedAt = time.Now().UTC()
					p.State = check(probe, ids[i])
					if ctx.Err() != nil && p.State == "unavailable" {
						p.State = "unknown"
						p.CheckedAt = time.Time{}
					}
					cancel()
				}
				out[i] = p
			}
		}()
	}
	for i := range ids {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}
