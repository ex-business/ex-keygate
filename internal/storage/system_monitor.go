package storage

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"ex-keygate/internal/access"
	"fmt"
	"sort"
	"time"
)

type AuthMinute struct {
	Minute  time.Time `json:"minute"`
	Kind    string    `json:"kind"`
	Success int64     `json:"success"`
	Denied  int64     `json:"denied"`
	Errors  int64     `json:"errors"`
}
type PluginObservation struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	CheckedAt time.Time `json:"checkedAt"`
}
type DatabaseObservation struct {
	ID         string    `json:"id"`
	Healthy    bool      `json:"healthy"`
	ObservedAt time.Time `json:"observedAt"`
}
type MonitorNode struct {
	ID          string    `json:"id"`
	Generation  uint64    `json:"generation"`
	Incarnation uint64    `json:"incarnation"`
	ExpiresAt   time.Time `json:"expiresAt"`
	State       string    `json:"state"`
}
type AuthSummary struct {
	Kind        string   `json:"kind"`
	Success     int64    `json:"success"`
	Denied      int64    `json:"denied"`
	Errors      int64    `json:"errors"`
	FailureRate *float64 `json:"failureRate"`
}
type MonitorCertificate struct {
	Kind     string     `json:"kind"`
	ID       string     `json:"id"`
	NotAfter *time.Time `json:"notAfter"`
	State    string     `json:"state"`
}
type SystemAlert struct {
	Code      string    `json:"code"`
	Active    bool      `json:"active"`
	Count     int64     `json:"count"`
	Severity  string    `json:"severity"`
	ChangedAt time.Time `json:"changedAt"`
	CheckedAt time.Time `json:"checkedAt"`
}
type SystemEvent struct {
	NodeID     string    `json:"nodeId"`
	Sequence   uint64    `json:"sequence,string"`
	Code       string    `json:"code"`
	Active     bool      `json:"active"`
	Count      int64     `json:"count"`
	ObservedAt time.Time `json:"observedAt"`
	RecordedAt time.Time `json:"recordedAt"`
}
type SystemMonitorView struct {
	SampledAt       time.Time            `json:"sampledAt"`
	LatestSample    *time.Time           `json:"latestSample"`
	Nodes           []MonitorNode        `json:"nodes"`
	Auth            []AuthSummary        `json:"auth"`
	Plugins         []PluginObservation  `json:"plugins"`
	Certificates    []MonitorCertificate `json:"certificates"`
	Alerts          []SystemAlert        `json:"alerts"`
	Events          []SystemEvent        `json:"events"`
	MissingNodes    int                  `json:"missingNodes"`
	Incomplete      bool                 `json:"incomplete"`
	ActiveProcesses int                  `json:"activeProcesses"`
}

// 数据库探测独立于依赖数据库的管理鉴权和告警写入，故障日志不能因数据库不可写而消失。
func (s *Store) MonitorDatabase(ctx context.Context) error { return s.db.PingContext(ctx) }
func (c *DevelopmentControl) MonitorProviderTargets(ctx context.Context) ([]string, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT provider_id FROM keygate.provider_policies WHERE environment=$1 AND enabled ORDER BY provider_id LIMIT 128`, c.environment)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	return out, tx.Commit()
}

// SaveMonitorSample 只由可信后台提交固定类别累计值，不在认证事务内写监控；同进程同分钟快照重复保存不增加计数。
func (c *DevelopmentControl) SaveMonitorSample(ctx context.Context, process, node string, auth []AuthMinute, plugins []PluginObservation, dbEvents []DatabaseObservation) error {
	if !access.ValidID(process) || (node != "" && !access.ValidID(node)) || len(auth) > 40 || len(plugins) > 128 || len(dbEvents) > 64 {
		return ErrInvalid
	}
	for _, v := range auth {
		switch v.Kind {
		case "hmac", "h5", "password", "oidc":
		default:
			return ErrInvalid
		}
		if v.Success < 0 || v.Denied < 0 || v.Errors < 0 || v.Success > 1e9 || v.Denied > 1e9 || v.Errors > 1e9 {
			return ErrInvalid
		}
	}
	for _, p := range plugins {
		if !access.ValidID(p.ID) || (p.State != "ready" && p.State != "unavailable" && p.State != "reserved" && p.State != "unknown") {
			return ErrInvalid
		}
	}
	for _, d := range dbEvents {
		if !access.ValidID(d.ID) || d.ObservedAt.IsZero() {
			return ErrInvalid
		}
	}
	a, e := json.Marshal(auth)
	if e != nil {
		return e
	}
	p, e := json.Marshal(plugins)
	if e != nil {
		return e
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, generation, incarnation := c.store.NodeIdentity()
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.system_monitor_samples(environment,process_id,node_id,auth,plugins,generation,incarnation) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(environment,process_id) DO UPDATE SET auth=EXCLUDED.auth,plugins=EXCLUDED.plugins,sampled_at=clock_timestamp()`, c.environment, process, node, a, p, generation, incarnation); e != nil {
		return e
	}
	for _, d := range dbEvents {
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.system_monitor_events(environment,event_id,node_id,code,active,count,observed_at) VALUES($1,$2,$3,'database',$4,1,$5) ON CONFLICT(environment,event_id) DO NOTHING`, c.environment, d.ID, node, !d.Healthy, d.ObservedAt); e != nil {
			return e
		}
	}
	// 高频样本只保留一天，事件历史独立保存；删除监控样本不改变任何授权或认证状态。
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.system_monitor_samples WHERE environment=$1 AND sampled_at<clock_timestamp()-interval '1 day'`, c.environment); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *DevelopmentControl) monitorView(ctx context.Context, tx *sql.Tx) (SystemMonitorView, error) {
	out := SystemMonitorView{Nodes: []MonitorNode{}, Auth: []AuthSummary{}, Plugins: []PluginObservation{}, Certificates: []MonitorCertificate{}, Alerts: []SystemAlert{}, Events: []SystemEvent{}}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return out, e
	}
	out.SampledAt = now
	rows, e := tx.QueryContext(ctx, `SELECT n.node_id,n.cluster_generation,n.incarnation,n.expires_at,CASE WHEN n.drained THEN 'drained' WHEN n.cluster_generation<>c.generation THEN 'fenced' WHEN n.expires_at<=clock_timestamp() THEN 'expired' ELSE 'active' END FROM keygate.runtime_nodes n JOIN keygate.runtime_cluster c ON c.singleton JOIN keygate.persistent_deployments d ON d.deployment_id=c.cluster_id WHERE d.environment=$1 ORDER BY n.node_id LIMIT 256`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var n MonitorNode
		if e = rows.Scan(&n.ID, &n.Generation, &n.Incarnation, &n.ExpiresAt, &n.State); e != nil {
			rows.Close()
			return out, e
		}
		out.Nodes = append(out.Nodes, n)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	if len(out.Nodes) >= 256 {
		out.Incomplete = true
	}
	rows, e = tx.QueryContext(ctx, `SELECT auth,plugins,sampled_at,node_id,generation,incarnation FROM keygate.system_monitor_samples WHERE environment=$1 AND sampled_at>=clock_timestamp()-interval '5 minutes' ORDER BY process_id LIMIT 256`, c.environment)
	if e != nil {
		return out, e
	}
	totals := map[string]*AuthSummary{}
	for _, kind := range []string{"hmac", "h5", "password", "oidc"} {
		totals[kind] = &AuthSummary{Kind: kind}
	}
	pluginMap := map[string]PluginObservation{}
	sampledProcesses := 0
	freshNodes := map[string]bool{}
	for rows.Next() {
		sampledProcesses++
		var authRaw, pluginRaw []byte
		var sampled time.Time
		var sampleNode string
		var generation, incarnation uint64
		if e = rows.Scan(&authRaw, &pluginRaw, &sampled, &sampleNode, &generation, &incarnation); e != nil {
			rows.Close()
			return out, e
		}
		if out.LatestSample == nil || sampled.After(*out.LatestSample) {
			t := sampled
			out.LatestSample = &t
		}
		if now.Sub(sampled) <= 45*time.Second {
			out.ActiveProcesses++
			freshNodes[fmt.Sprintf("%s/%d/%d", sampleNode, generation, incarnation)] = true
		}
		var a []AuthMinute
		var ps []PluginObservation
		if json.Unmarshal(authRaw, &a) != nil || json.Unmarshal(pluginRaw, &ps) != nil {
			rows.Close()
			return out, ErrConflict
		}
		for _, v := range a {
			if v.Minute.Before(now.Truncate(time.Minute).Add(-4*time.Minute)) || v.Minute.After(now) {
				continue
			}
			t := totals[v.Kind]
			if t == nil {
				rows.Close()
				return out, ErrConflict
			}
			t.Success += v.Success
			t.Denied += v.Denied
			t.Errors += v.Errors
		}
		if now.Sub(sampled) <= 45*time.Second {
			for _, p := range ps {
				old, ok := pluginMap[p.ID]
				rank := map[string]int{"reserved": 0, "ready": 1, "unknown": 2, "unavailable": 3}
				if !ok || rank[p.State] > rank[old.State] {
					pluginMap[p.ID] = p
				} else if old.State == p.State && p.CheckedAt.After(old.CheckedAt) {
					pluginMap[p.ID] = p
				}
			}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	for _, n := range out.Nodes {
		if n.State == "active" && !freshNodes[fmt.Sprintf("%s/%d/%d", n.ID, n.Generation, n.Incarnation)] {
			out.MissingNodes++
		}
	}
	if sampledProcesses >= 256 {
		out.Incomplete = true
	}
	for _, kind := range []string{"hmac", "h5", "password", "oidc"} {
		t := totals[kind]
		if t.Success+t.Denied > 0 {
			rate := float64(t.Denied) / float64(t.Success+t.Denied)
			t.FailureRate = &rate
		}
		out.Auth = append(out.Auth, *t)
	}
	for _, p := range pluginMap {
		out.Plugins = append(out.Plugins, p)
	}
	sort.Slice(out.Plugins, func(i, j int) bool { return out.Plugins[i].ID < out.Plugins[j].ID })
	// 仅公开证书进入解析，在线服务不接触根私钥；当前指针、启停与数据库时间共同决定到期告警。
	rows, e = tx.QueryContext(ctx, `SELECT 'root',fingerprint,certificate FROM keygate.application_trust_roots WHERE environment=$1 UNION ALL SELECT 'status',root_fingerprint,certificate FROM keygate.application_trust_status_signers WHERE environment=$1 UNION ALL SELECT 'service',s.service_id,c.certificate FROM keygate.application_trust_services s JOIN keygate.application_trust_certificates c ON c.environment=s.environment AND c.service_id=s.service_id AND c.version=s.active_version WHERE s.environment=$1 AND NOT s.disabled AND c.state='active' LIMIT 1000`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var cert MonitorCertificate
		var raw []byte
		if e = rows.Scan(&cert.Kind, &cert.ID, &raw); e != nil {
			rows.Close()
			return out, e
		}
		v, e := x509.ParseCertificate(raw)
		if e != nil {
			cert.State = "invalid"
		} else {
			cert.NotAfter = &v.NotAfter
			switch {
			case v.NotBefore.After(now):
				cert.State = "invalid"
			case !v.NotAfter.After(now):
				cert.State = "expired"
			case v.NotAfter.Sub(now) <= time.Hour:
				cert.State = "due_1h"
			case v.NotAfter.Sub(now) <= 24*time.Hour:
				cert.State = "due_24h"
			case v.NotAfter.Sub(now) <= 7*24*time.Hour:
				cert.State = "due_7d"
			default:
				cert.State = "valid"
			}
		}
		out.Certificates = append(out.Certificates, cert)
	}
	e = rows.Err()
	rows.Close()
	if len(out.Certificates) >= 1000 {
		out.Incomplete = true
	}
	return out, e
}

// CollectSystemAlerts 共享域锁去重告警触发/恢复，所有节点看到同一权威状态；日志只在提交后输出。
func (c *DevelopmentControl) CollectSystemAlerts(ctx context.Context) ([]SystemAlert, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	view, e := c.monitorView(ctx, tx)
	if e != nil {
		return nil, e
	}
	var inactive, deniedKinds, systemErrors, pluginFailures, pluginUnknown, due, expired, invalid int64
	for _, n := range view.Nodes {
		if n.State == "expired" || n.State == "fenced" {
			inactive++
		}
	}
	for _, a := range view.Auth {
		if a.Success+a.Denied >= 20 && a.FailureRate != nil && *a.FailureRate >= .2 {
			deniedKinds++
		}
		systemErrors += a.Errors
	}
	for _, p := range view.Plugins {
		if p.State == "unavailable" {
			pluginFailures++
		} else if p.State == "unknown" {
			pluginUnknown++
		}
	}
	for _, cert := range view.Certificates {
		switch cert.State {
		case "expired":
			expired++
		case "invalid":
			invalid++
		case "due_1h", "due_24h", "due_7d":
			due++
		}
	}
	missing := int64(view.MissingNodes)
	if view.ActiveProcesses == 0 {
		missing++
	}
	incomplete := int64(0)
	if view.Incomplete {
		incomplete = 1
	}
	conditions := []SystemAlert{{Code: "monitor_incomplete", Count: incomplete, Severity: "warning"}, {Code: "node_expired", Count: inactive, Severity: "critical"}, {Code: "auth_failure_rate", Count: deniedKinds, Severity: "warning"}, {Code: "auth_system_error", Count: systemErrors, Severity: "critical"}, {Code: "plugin_unknown", Count: pluginUnknown, Severity: "warning"}, {Code: "plugin_unavailable", Count: pluginFailures, Severity: "warning"}, {Code: "certificate_due", Count: due, Severity: "warning"}, {Code: "certificate_expired", Count: expired, Severity: "critical"}, {Code: "certificate_invalid", Count: invalid, Severity: "critical"}, {Code: "monitor_stale", Count: missing, Severity: "critical"}}
	changed := []SystemAlert{}
	for _, a := range conditions {
		a.Active = a.Count > 0
		var previous bool
		e = tx.QueryRowContext(ctx, `SELECT active FROM keygate.system_monitor_alerts WHERE environment=$1 AND code=$2`, c.environment, a.Code).Scan(&previous)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.system_monitor_alerts(environment,code,active,count,severity) VALUES($1,$2,$3,$4,$5) ON CONFLICT(environment,code) DO UPDATE SET active=EXCLUDED.active,count=EXCLUDED.count,severity=EXCLUDED.severity,checked_at=clock_timestamp(),changed_at=CASE WHEN system_monitor_alerts.active<>EXCLUDED.active THEN clock_timestamp() ELSE system_monitor_alerts.changed_at END`, c.environment, a.Code, a.Active, a.Count, a.Severity); e != nil {
			return nil, e
		}
		if previous != a.Active {
			id, idErr := controlID()
			if idErr != nil {
				return nil, idErr
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.system_monitor_events(environment,event_id,code,active,count,observed_at) VALUES($1,$2,$3,$4,$5,clock_timestamp())`, c.environment, "monitor-"+id, a.Code, a.Active, a.Count); e != nil {
				return nil, e
			}
			changed = append(changed, a)
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return changed, nil
}
func (c *DevelopmentControl) SystemMonitor(ctx context.Context, token string) (SystemMonitorView, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, e := c.begin(ctx)
	if e != nil {
		return SystemMonitorView{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return SystemMonitorView{}, e
	}
	if !c.has(ctx, tx, a.id, access.PolicyAdmin, "") && !c.has(ctx, tx, a.id, access.Auditor, "") {
		return SystemMonitorView{}, ErrDenied
	}
	out, e := c.monitorView(ctx, tx)
	if e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT code,active,count,severity,changed_at,checked_at FROM keygate.system_monitor_alerts WHERE environment=$1 ORDER BY code`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var a SystemAlert
		if e = rows.Scan(&a.Code, &a.Active, &a.Count, &a.Severity, &a.ChangedAt, &a.CheckedAt); e != nil {
			rows.Close()
			return out, e
		}
		out.Alerts = append(out.Alerts, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.QueryContext(ctx, `SELECT sequence,node_id,code,active,count,observed_at,recorded_at FROM keygate.system_monitor_events WHERE environment=$1 ORDER BY sequence DESC LIMIT 100`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var v SystemEvent
		if e = rows.Scan(&v.Sequence, &v.NodeID, &v.Code, &v.Active, &v.Count, &v.ObservedAt, &v.RecordedAt); e != nil {
			rows.Close()
			return out, e
		}
		out.Events = append(out.Events, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}
