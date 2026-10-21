package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSystemMonitoringSnapshotsPermissionsAndRecovery(t *testing.T) {
	f := newControlFixture(t)
	opsAdmin(t, f)
	ctx := context.Background()
	if _, e := f.c.SystemMonitor(ctx, f.tokens[1]); !errors.Is(e, ErrDenied) {
		t.Fatal("普通审批人越权", e)
	}
	grantAuditor(t, f, 4, "one")
	if _, e := f.c.SystemMonitor(ctx, f.tokens[4]); !errors.Is(e, ErrDenied) {
		t.Fatal("局部审计越权", e)
	}
	a := []AuthMinute{{Minute: time.Now().UTC().Truncate(time.Minute), Kind: "hmac", Denied: 20, Errors: 2}}
	events := []DatabaseObservation{{ID: unique(t), Healthy: false, ObservedAt: time.Now().UTC()}, {ID: unique(t), Healthy: true, ObservedAt: time.Now().UTC()}}
	for i := 0; i < 2; i++ {
		if e := f.c.SaveMonitorSample(ctx, "process-one", "", a, []PluginObservation{{ID: "test-plugin", State: "unavailable", CheckedAt: time.Now().UTC()}}, events); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.c.CollectSystemAlerts(ctx); e != nil {
		t.Fatal(e)
	}
	v, e := f.c.SystemMonitor(ctx, f.tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	if v.Auth[0].Denied != 20 || v.Auth[0].Errors != 2 || v.Auth[0].FailureRate == nil || *v.Auth[0].FailureRate != 1 {
		t.Fatal("重复快照增加统计", v.Auth)
	}
	active := map[string]bool{}
	for _, a := range v.Alerts {
		active[a.Code] = a.Active
	}
	if !active["auth_failure_rate"] || !active["auth_system_error"] || !active["plugin_unavailable"] {
		t.Fatal("漏报阈值", active)
	}
	count := 0
	for _, ev := range v.Events {
		if ev.Code == "database" {
			count++
		}
	}
	if count != 2 {
		t.Fatal("数据库转换重复", count)
	}
	if e = f.c.SaveMonitorSample(ctx, "process-one", "", nil, []PluginObservation{{ID: "test-plugin", State: "ready", CheckedAt: time.Now().UTC()}}, nil); e != nil {
		t.Fatal(e)
	}
	changed, e := f.c.CollectSystemAlerts(ctx)
	if e != nil {
		t.Fatal(e)
	}
	recovered := map[string]bool{}
	for _, a := range changed {
		if !a.Active {
			recovered[a.Code] = true
		}
	}
	if !recovered["auth_failure_rate"] || !recovered["auth_system_error"] || !recovered["plugin_unavailable"] {
		t.Fatal("恢复未记录", recovered)
	}
	v, e = f.c.SystemMonitor(ctx, f.tokens[0])
	if e != nil || v.Auth[0].FailureRate != nil {
		t.Fatal("无样本伪造正常率", e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.system_monitor_samples SET sampled_at=clock_timestamp()-interval '46 seconds' WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.CollectSystemAlerts(ctx); e != nil {
		t.Fatal(e)
	}
	v, e = f.c.SystemMonitor(ctx, f.tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range v.Alerts {
		if a.Code == "monitor_stale" && !a.Active {
			t.Fatal("陈旧样本未告警")
		}
	}
}

func TestSystemMonitoringCertificateAndInstanceIdentity(t *testing.T) {
	f := newControlFixture(t)
	opsAdmin(t, f)
	ctx := context.Background()
	// 测试专用库构造当前租约和旧实例快照，不变更真实部署。
	fingerprint := strings.Repeat("a", 64)
	if _, e := f.db.Exec(`INSERT INTO keygate.persistent_deployments(environment,deployment_id,revision,config_hash,profile_hash,protocol,schema_version) VALUES($1,'monitor-test-deployment',1,$2,$2,1,24)`, f.c.environment, fingerprint); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`UPDATE keygate.runtime_cluster SET cluster_id='monitor-test-deployment'; INSERT INTO keygate.runtime_nodes(node_id,cluster_generation,incarnation,instance_hash,expires_at) SELECT 'monitor-node',generation,2,decode(repeat('a',64),'hex'),clock_timestamp()+interval '1 minute' FROM keygate.runtime_cluster`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		f.db.Exec(`DELETE FROM keygate.runtime_nodes WHERE node_id='monitor-node'; UPDATE keygate.runtime_cluster SET cluster_id=''`)
	})
	if e := f.c.SaveMonitorSample(ctx, "old-process", "monitor-node", nil, nil, nil); e != nil {
		t.Fatal(e)
	}
	v, e := f.c.SystemMonitor(ctx, f.tokens[0])
	if e != nil || v.MissingNodes != 1 {
		t.Fatal("旧实例样本掩盖新实例", v.MissingNodes, e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.system_monitor_samples SET generation=(SELECT generation FROM keygate.runtime_cluster),incarnation=2 WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	v, e = f.c.SystemMonitor(ctx, f.tokens[0])
	if e != nil || v.MissingNodes != 0 {
		t.Fatal("当前实例仍缺失", v.MissingNodes, e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Exec(`INSERT INTO keygate.application_trust_roots(environment,application_environment,fingerprint,certificate) VALUES($1,'monitor-test',$2,$3)`, f.c.environment, fingerprint, der); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.CollectSystemAlerts(ctx); e != nil {
		t.Fatal(e)
	}
	v, e = f.c.SystemMonitor(ctx, f.tokens[0])
	if e != nil || len(v.Certificates) != 1 || v.Certificates[0].State != "due_1h" {
		t.Fatal("证书到期告警", v.Certificates, e)
	}
	cert.NotAfter = time.Now().Add(-time.Minute)
	der, e = x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.application_trust_roots SET certificate=$2 WHERE environment=$1`, f.c.environment, der); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.CollectSystemAlerts(ctx); e != nil {
		t.Fatal(e)
	}
	v, e = f.c.SystemMonitor(ctx, f.tokens[0])
	if e != nil || v.Certificates[0].State != "expired" {
		t.Fatal("过期证书漏报", e)
	}
}
