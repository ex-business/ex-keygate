package webauth

import (
	"bytes"
	"context"
	"database/sql"
	"ex-keygate/internal/storage"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMonitoringResultsAndDatabaseTransitions(t *testing.T) {
	s := &Service{}
	for _, status := range []int{200, 401, 403, 503} {
		r := httptest.NewRecorder()
		w, finish := s.observeAuthentication(r, "hmac")
		w.Header().Set("X-Test", "kept")
		w.WriteHeader(status)
		finish()
		if r.Code != status || r.Header().Get("X-Test") != "kept" {
			t.Fatal("监控改变响应")
		}
	}
	_, a, _ := s.monitor.snapshot()
	if len(a) != 1 || a[0].Success != 1 || a[0].Denied != 2 || a[0].Errors != 1 {
		t.Fatal("结果分类错误", a)
	}
	s.monitor.record("arbitrary", 401)
	_, a, _ = s.monitor.snapshot()
	if len(a) != 1 {
		t.Fatal("允许无限类别")
	}
	m := &runtimeMonitor{}
	if changed, _ := m.databaseObservation(true); changed {
		t.Fatal("初始健康不应告警")
	}
	for i := 0; i < 70; i++ {
		m.databaseObservation(i%2 != 0)
	}
	_, _, events := m.snapshot()
	if len(events) != 64 || m.lost != 6 {
		t.Fatal("故障队列无界", len(events), m.lost)
	}
	m.acknowledge(events[:1])
	_, _, events = m.snapshot()
	if len(events) != 63 {
		t.Fatal("确认事件失败")
	}
}
func TestMonitoringPanicPreserved(t *testing.T) {
	s := &Service{}
	func() {
		defer func() {
			if recover() != "original" {
				t.Fatal("异常被吞掉")
			}
		}()
		_, finish := s.observeAuthentication(httptest.NewRecorder(), "password")
		defer finish()
		panic("original")
	}()
	_, a, _ := s.monitor.snapshot()
	if len(a) != 1 || a[0].Errors != 1 {
		t.Fatal("异常未计系统错误")
	}
}
func TestMonitoringProbeBudgetIsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	rows := probeMonitorPlugins(ctx, []string{"one", "two"}, func(context.Context, string) string { called = true; return "unavailable" })
	for _, p := range rows {
		if p.State != "unknown" || !p.CheckedAt.IsZero() {
			t.Fatal("未探测伪报故障", p)
		}
	}
	if called {
		t.Fatal("预算耗尽仍探测")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	rows = probeMonitorPlugins(ctx, []string{"one"}, func(c context.Context, _ string) string { <-c.Done(); return "unavailable" })
	if rows[0].State != "unknown" {
		t.Fatal("整批取消伪报插件故障")
	}
	rows = probeMonitorPlugins(context.Background(), []string{"one"}, func(context.Context, string) string { return "unavailable" })
	if rows[0].State != "unavailable" {
		t.Fatal("真实故障漏报")
	}
}

func TestMonitoringDatabaseFailureLogsWithoutDatabaseWrite(t *testing.T) {
	db, e := sql.Open("pgx", "host=127.0.0.1 port=1 user=test password=never-log-this dbname=unavailable connect_timeout=1 sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	store, e := storage.New(db)
	if e != nil {
		t.Fatal(e)
	}
	var logs bytes.Buffer
	s := &Service{store: store, flow: &developmentFlow{environment: "monitor-test"}, logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s.RunMonitoring(ctx)
	if !strings.Contains(logs.String(), "数据库监测异常") || strings.Contains(logs.String(), "never-log-this") {
		t.Fatal("数据库失败日志缺失或泄密")
	}
	_, _, events := s.monitor.snapshot()
	if len(events) != 1 || events[0].Healthy {
		t.Fatal("故障未留待恢复提交")
	}
}
