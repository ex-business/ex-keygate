package storage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type alertSink struct {
	mu    sync.Mutex
	calls []AlertMessage
	fail  bool
	hook  func()
}

func (s *alertSink) SendSystemAlert(_ context.Context, v AlertMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, v)
	if s.hook != nil {
		s.hook()
	}
	if s.fail {
		return errors.New("模拟发送失败")
	}
	return nil
}
func alertSetup(t *testing.T, f controlFixture) (map[string]AlertBinding, *alertSink) {
	t.Helper()
	sink := &alertSink{}
	routes := []AlertRoute{{ID: "operations", Channel: "email", Target: "oncall", Digest: strings.Repeat("a", 64)}, {ID: "escalation", Channel: "sms", Target: "leader", Level: 1, EscalationSeconds: 60, Digest: strings.Repeat("b", 64)}, {ID: "webhook", Channel: "webhook", Target: "incident-bus", Digest: strings.Repeat("c", 64)}}
	if e := f.c.ConfigureAlertRoutes(context.Background(), routes); e != nil {
		t.Fatal(e)
	}
	bindings := map[string]AlertBinding{}
	for _, r := range routes {
		bindings[r.ID] = AlertBinding{Route: r, Plugin: sink}
	}
	return bindings, sink
}
func alertEvent(t *testing.T, f controlFixture, active bool) string {
	t.Helper()
	id := unique(t)
	if _, e := f.db.Exec(`INSERT INTO keygate.system_monitor_events(environment,event_id,node_id,code,active,count,observed_at) VALUES($1,$2,'','plugin_unavailable',$3,1,clock_timestamp())`, f.c.environment, id, active); e != nil {
		t.Fatal(e)
	}
	return id
}
func alertCollect(t *testing.T, f controlFixture) {
	t.Helper()
	if e := f.c.CollectAlertDeliveries(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestAlertDeliveryRetryDedupEscalationAndRecovery(t *testing.T) {
	f := newControlFixture(t)
	opsAdmin(t, f)
	ctx := context.Background()
	bindings, sink := alertSetup(t, f)
	sink.fail = true
	incident := alertEvent(t, f, true)
	alertCollect(t, f)
	alertCollect(t, f)
	var count int
	if e := f.db.QueryRow(`SELECT count(*) FROM keygate.alert_deliveries WHERE environment=$1`, f.c.environment).Scan(&count); e != nil || count != 2 {
		t.Fatal("重复生成通知", count, e)
	}
	// 多节点领取相同任务，只允许每个任务存在一个有效发送者。
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := f.c.DispatchAlertDelivery(ctx, bindings); errs <- e }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if len(sink.calls) != 2 {
		t.Fatal("并发重复发送", len(sink.calls))
	}
	first := sink.calls[0]
	for i := 0; i < 4; i++ {
		if _, e := f.db.Exec(`UPDATE keygate.alert_deliveries SET next_attempt=clock_timestamp() WHERE environment=$1 AND id=$2`, f.c.environment, first.ID); e != nil {
			t.Fatal(e)
		}
		if _, e := f.c.DispatchAlertDelivery(ctx, bindings); e != nil {
			t.Fatal(e)
		}
	}
	var state string
	var attempts int
	if e := f.db.QueryRow(`SELECT state,attempts FROM keygate.alert_deliveries WHERE environment=$1 AND id=$2`, f.c.environment, first.ID).Scan(&state, &attempts); e != nil || state != "failed" || attempts != 5 {
		t.Fatal("重试未收敛", state, attempts, e)
	}
	for _, v := range sink.calls {
		if v.RouteID == first.RouteID && (v.ID != first.ID || v.EventID != first.EventID || v.ObservedAt != first.ObservedAt) {
			t.Fatal("重试改变幂等载荷")
		}
	}
	if _, e := f.db.Exec(`UPDATE keygate.alert_incidents SET opened_at=clock_timestamp()-interval '61 seconds' WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`UPDATE keygate.alert_routes SET starts_at=clock_timestamp()-interval '2 minutes' WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	alertCollect(t, f)
	alertCollect(t, f)
	if e := f.db.QueryRow(`SELECT count(*) FROM keygate.alert_deliveries WHERE environment=$1 AND kind='escalation'`, f.c.environment).Scan(&count); e != nil || count != 1 {
		t.Fatal("升级漏报或重复", count, e)
	}
	sink.fail = false
	if _, e := f.c.DispatchAlertDelivery(ctx, bindings); e != nil {
		t.Fatal(e)
	}
	alertEvent(t, f, false)
	alertCollect(t, f)
	view, e := f.c.AlertDeliveries(ctx, f.tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	recovered := 0
	for _, v := range view.Deliveries {
		if v.Kind == "recovery" {
			recovered++
		}
		if v.IncidentID != incident {
			t.Fatal("事故标识变化")
		}
		if v.Kind != "recovery" && (v.State == "pending" || v.State == "sending") {
			t.Fatal("恢复后旧任务仍可发")
		}
	}
	if recovered != 3 {
		t.Fatal("恢复收件范围错误", recovered)
	}
}
func TestAlertDeliverySilencePermissionsAndLeaseRecovery(t *testing.T) {
	f := newControlFixture(t)
	opsAdmin(t, f)
	ctx := context.Background()
	bindings, sink := alertSetup(t, f)
	alertEvent(t, f, true)
	alertCollect(t, f)
	if e := f.c.SetAlertSilence(ctx, f.tokens[1], "plugin_unavailable", "越权静默", unique(t), 900); !errors.Is(e, ErrDenied) {
		t.Fatal("普通审批人静默", e)
	}
	grantAuditor(t, f, 2, "")
	if e := f.c.SetAlertSilence(ctx, f.tokens[2], "plugin_unavailable", "只读审计不能静默", unique(t), 900); !errors.Is(e, ErrDenied) {
		t.Fatal("审计员静默", e)
	}
	grantAuditor(t, f, 4, "one")
	if _, e := f.c.AlertDeliveries(ctx, f.tokens[4]); !errors.Is(e, ErrDenied) {
		t.Fatal("局部权限越权", e)
	}
	if e := f.c.SetAlertSilence(ctx, f.tokens[0], "plugin_unavailable", "维护窗口暂停通知", unique(t), 86401); !errors.Is(e, ErrInvalid) {
		t.Fatal("静默无期限", e)
	}
	if e := f.c.SetAlertSilence(ctx, f.tokens[0], "plugin_unavailable", "维护窗口暂停通知", unique(t), 900); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e := f.c.DispatchAlertDelivery(ctx, bindings); e != nil {
			t.Fatal(e)
		}
	}
	if len(sink.calls) != 0 {
		t.Fatal("静默仍投递")
	}
	var attempts int
	f.db.QueryRow(`SELECT max(attempts) FROM keygate.alert_deliveries WHERE environment=$1`, f.c.environment).Scan(&attempts)
	if attempts != 0 {
		t.Fatal("静默消耗尝试")
	}
	if e := f.c.SetAlertSilence(ctx, f.tokens[0], "plugin_unavailable", "维护结束恢复通知", unique(t), 0); e != nil {
		t.Fatal(e)
	}
	// 模拟发送者崩溃且已经耗尽最后一次预算，扫描必须收敛并保留未知结果记录。
	var id string
	if e := f.db.QueryRow(`UPDATE keygate.alert_deliveries SET state='sending',attempts=5,lease_until=clock_timestamp()-interval '1 second' WHERE environment=$1 AND route_id='operations' RETURNING id`, f.c.environment).Scan(&id); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`INSERT INTO keygate.alert_delivery_records(environment,delivery_id,attempt,outcome) VALUES($1,$2,5,'sending')`, f.c.environment, id); e != nil {
		t.Fatal(e)
	}
	alertCollect(t, f)
	v, e := f.c.AlertDeliveries(ctx, f.tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, r := range v.Records {
		if r.DeliveryID == id && r.Outcome == "lease_expired" {
			found = true
		}
	}
	if !found {
		t.Fatal("崩溃投递未记录")
	}
	if _, e = f.c.DispatchAlertDelivery(ctx, bindings); e != nil {
		t.Fatal(e)
	}
	if len(sink.calls) != 1 {
		t.Fatal("解除静默后未发送")
	}
}
func TestAlertDeliveryLateResultAndConfigChange(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	bindings, sink := alertSetup(t, f)
	alertEvent(t, f, true)
	alertCollect(t, f)
	sink.hook = func() { alertEvent(t, f, false); alertCollect(t, f) }
	if _, e := f.c.DispatchAlertDelivery(ctx, bindings); e != nil {
		t.Fatal(e)
	}
	var state string
	if e := f.db.QueryRow(`SELECT state FROM keygate.alert_deliveries WHERE environment=$1 AND id=$2`, f.c.environment, sink.calls[0].ID).Scan(&state); e != nil || state != "obsolete" {
		t.Fatal("迟到成功复活任务", state, e)
	}
	if e := f.c.ConfigureAlertRoutes(ctx, nil); e != nil {
		t.Fatal(e)
	}
	if worked, e := f.c.DispatchAlertDelivery(ctx, bindings); e != nil || worked {
		t.Fatal("删除路由仍发送", worked, e)
	}
}

func TestAlertDeliveryQuarantineDoesNotReplayHistory(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	bindings, sink := alertSetup(t, f)
	alertEvent(t, f, true)
	alertCollect(t, f)
	checkpoint, e := f.c.store.CaptureSafetyCheckpoint(ctx, f.c.environment)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.store.QuarantineRestored(ctx, checkpoint, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = f.c.ConfigureAlertRoutes(ctx, []AlertRoute{bindings["operations"].Route, bindings["escalation"].Route, bindings["webhook"].Route}); e != nil {
		t.Fatal(e)
	}
	alertCollect(t, f)
	if worked, e := f.c.DispatchAlertDelivery(ctx, bindings); e != nil || worked || len(sink.calls) != 0 {
		t.Fatal("恢复后重放旧告警", worked, e)
	}
	alertEvent(t, f, true)
	alertCollect(t, f)
	if worked, e := f.c.DispatchAlertDelivery(ctx, bindings); e != nil || !worked || len(sink.calls) != 1 {
		t.Fatal("恢复后新告警丢失", worked, e)
	}
}
