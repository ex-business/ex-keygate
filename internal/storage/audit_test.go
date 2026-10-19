package storage

import (
	"context"
	"encoding/json"
	"errors"
	"ex-keygate/internal/access"
	"strings"
	"testing"
	"time"
)

func grantAuditor(t *testing.T, f controlFixture, who int, scope string) {
	t.Helper()
	if _, e := f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,'auditor',$3)`, f.c.environment, f.bootstrap.Principals[who].ID, scope); e != nil {
		t.Fatal(e)
	}
}
func auditFilter(client string) AuditFilter {
	return AuditFilter{ClientID: client, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Minute), Limit: 100}
}
func TestAuditScopesSnapshotAndRevocation(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	for _, client := range []string{"one", "two"} {
		r := submitClient(t, f, client)
		approveControl(t, f, r)
		if e := f.c.ExecuteLocal(ctx, r.ID, r.Digest, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.c.AuditQuery(ctx, f.tokens[0], auditFilter("")); !errors.Is(e, ErrDenied) {
		t.Fatal("viewer取得审计", e)
	}
	grantAuditor(t, f, 0, "")
	grantAuditor(t, f, 4, "one")
	if _, e := f.c.AuditQuery(ctx, f.tokens[4], auditFilter("two")); !errors.Is(e, ErrDenied) {
		t.Fatal("审计越客户端", e)
	}
	if _, e := f.c.AuditQuery(ctx, f.tokens[4], auditFilter("")); !errors.Is(e, ErrDenied) {
		t.Fatal("局部审计查看全域", e)
	}
	rows, e := f.c.AuditQuery(ctx, f.tokens[4], auditFilter("one"))
	if e != nil || len(rows) == 0 {
		t.Fatal(rows, e)
	}
	for _, row := range rows {
		if row.ClientID != "one" {
			t.Fatal("混入其他范围", row)
		}
	}
	out, e := f.c.ExportAudit(ctx, f.tokens[4], auditFilter("one"), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := f.c.DownloadAudit(ctx, f.tokens[4], out.ID, unique(t))
	if e != nil || digestBytes(raw) != out.Digest {
		t.Fatal(e)
	}
	r := submitClient(t, f, "three")
	_ = r
	again, e := f.c.DownloadAudit(ctx, f.tokens[4], out.ID, unique(t))
	if e != nil || string(raw) != string(again) {
		t.Fatal("快照随分页变化", e)
	}
	if _, e = f.c.DownloadAudit(ctx, f.tokens[0], out.ID, unique(t)); e == nil {
		t.Fatal("其他审计人下载私有导出")
	}
	list, e := f.c.AuditExports(ctx, f.tokens[4])
	if e != nil || len(list) != 1 {
		t.Fatal(list, e)
	}
	for _, forbidden := range []string{"ciphertext", "token", "recipientPublicKey", "nonce", "cookie"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("敏感字段入导出", forbidden)
		}
	}
	if _, e = f.db.Exec(`UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND role=$3`, f.c.environment, f.bootstrap.Principals[4].ID, access.Auditor); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.DownloadAudit(ctx, f.tokens[4], out.ID, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("撤权后下载", e)
	}
}

type memorySink struct {
	data map[string][]byte
	fail bool
}

func (m *memorySink) Put(_ context.Context, id string, raw []byte) (string, error) {
	if m.fail {
		return "", errors.New("独立存储不可用")
	}
	if old := m.data[id]; old != nil && string(old) != string(raw) {
		return "", ErrConflict
	}
	m.data[id] = append([]byte(nil), raw...)
	return digestBytes(raw), nil
}
func TestAuditOutboxAndFailureAggregation(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	r := submitClient(t, f, "one")
	_ = r
	sink := &memorySink{data: map[string][]byte{}, fail: true}
	if _, e := f.c.store.ArchiveAuditBatch(ctx, f.c.environment, sink, 1000); e == nil {
		t.Fatal("归档失败被吞")
	}
	sink.fail = false
	n, e := f.c.store.ArchiveAuditBatch(ctx, f.c.environment, sink, 1000)
	if e != nil || n == 0 {
		t.Fatal(n, e)
	}
	n, e = f.c.store.ArchiveAuditBatch(ctx, f.c.environment, sink, 1000)
	if e != nil || n != 0 {
		t.Fatal("重复归档", n, e)
	}
	for _, raw := range sink.data {
		if e = f.c.store.CompareArchivedAudit(ctx, f.c.environment, raw); e != nil {
			t.Fatal(e)
		}
		var event AuditEvent
		_ = json.Unmarshal(raw, &event)
		if _, e = f.db.Exec(`UPDATE keygate.audit_events SET result='tampered' WHERE event_id=$1`, event.EventID); e != nil {
			t.Fatal(e)
		}
		if e = f.c.store.CompareArchivedAudit(ctx, f.c.environment, raw); !errors.Is(e, ErrConflict) {
			t.Fatal("篡改未发现", e)
		}
		break
	}
	for range 3 {
		if e = f.c.RecordAuthFailure(ctx, "denied", unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	grantAuditor(t, f, 0, "")
	buckets, e := f.c.AuthFailures(ctx, f.tokens[0])
	if e != nil || len(buckets) != 1 || buckets[0].Attempts != 3 {
		t.Fatal(buckets, e)
	}
	if e = f.c.RecordAuthFailure(ctx, "attacker-client", unique(t)); !errors.Is(e, ErrInvalid) {
		t.Fatal("无限原因维度", e)
	}
}
