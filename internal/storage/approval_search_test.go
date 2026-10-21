package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"ex-keygate/internal/manifest"
	"fmt"
	"testing"
	"time"
)

func TestApprovalSearchBeyondHundredAndRevocation(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	for i := 0; i < 105; i++ {
		submitClient(t, f, fmt.Sprintf("search-%03d", i))
	}
	q := SearchFilter{Query: "search-", View: "applicant", Limit: 20}
	seen := map[string]bool{}
	for {
		page, e := f.c.SearchRequests(ctx, f.tokens[0], q)
		if e != nil {
			t.Fatal(e)
		}
		for _, r := range page.Items {
			if seen[r.ID] {
				t.Fatal("重复申请")
			}
			seen[r.ID] = true
		}
		if page.Next == "" {
			break
		}
		q.Cursor = page.Next
	}
	if len(seen) != 105 {
		t.Fatal("历史申请被100条截断", len(seen))
	}
	first, e := f.c.SearchRequests(ctx, f.tokens[0], SearchFilter{Query: "search-000", Limit: 20})
	if e != nil || len(first.Items) != 1 {
		t.Fatal("名称搜索", e, len(first.Items))
	}
	excluded, e := f.c.SearchRequests(ctx, f.tokens[0], SearchFilter{From: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Limit: 20})
	if e != nil || len(excluded.Items) != 0 {
		t.Fatal("时间筛选", e)
	}
	nq := SearchFilter{Limit: 20}
	notices := map[string]bool{}
	for {
		page, e := f.c.SearchNotifications(ctx, f.tokens[1], nq)
		if e != nil {
			t.Fatal(e)
		}
		for _, n := range page.Items {
			if notices[n.ID] {
				t.Fatal("重复通知")
			}
			notices[n.ID] = true
		}
		if page.Next == "" {
			break
		}
		nq.Cursor = page.Next
	}
	if len(notices) != 105 {
		t.Fatal("历史通知被截断", len(notices))
	}
	page, e := f.c.SearchNotifications(ctx, f.tokens[1], SearchFilter{Limit: 1})
	if e != nil || page.Next == "" {
		t.Fatal(e)
	}
	if _, e = f.c.SearchNotifications(ctx, f.tokens[2], SearchFilter{Limit: 1, Cursor: page.Next}); !errors.Is(e, ErrInvalid) {
		t.Fatal("跨身份游标", e)
	}
	if _, e = f.c.SearchNotifications(ctx, f.tokens[1], SearchFilter{Limit: 1, Query: "changed", Cursor: page.Next}); !errors.Is(e, ErrInvalid) {
		t.Fatal("换条件复用游标", e)
	}
	if e = f.c.ReadApprovalNotification(ctx, f.tokens[1], page.Items[0].ID); e != nil {
		t.Fatal(e)
	}
	unread, e := f.c.SearchNotifications(ctx, f.tokens[1], SearchFilter{Limit: 50, Unread: true, Query: page.Items[0].ID})
	if e != nil || len(unread.Items) != 0 {
		t.Fatal("未读服务端过滤", e)
	}
	f.db.Exec(`UPDATE keygate.role_grants SET enabled=false WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[1].ID)
	revoked, e := f.c.SearchNotifications(ctx, f.tokens[1], SearchFilter{Limit: 1, Cursor: page.Next})
	if e != nil || len(revoked.Items) != 0 {
		t.Fatal("撤权后读取旧通知", e)
	}
	for _, bad := range []SearchFilter{{Limit: 51}, {Limit: -1}, {From: "bad"}, {From: "2026-01-02T00:00:00Z", Until: "2026-01-01T00:00:00Z"}, {Cursor: "bad"}, {Query: "bad\nquery"}} {
		if _, e = f.c.SearchRequests(ctx, f.tokens[0], bad); !errors.Is(e, ErrInvalid) {
			t.Fatal("非法过滤", bad, e)
		}
	}
}

func TestApprovalSearchCurrentEligibilityAndClosedMillisecond(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	f.db.Exec(`UPDATE keygate.control_policies SET sequential=true WHERE environment=$1`, f.c.environment)
	f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,'viewer','')`, f.c.environment, f.bootstrap.Principals[1].ID)
	submitClient(t, f, "search-current-one")
	submitClient(t, f, "search-current-two")
	time.Sleep(2 * time.Millisecond)
	mine, e := f.c.SearchRequests(ctx, f.tokens[1], SearchFilter{View: "mine", Limit: 20})
	if e != nil || len(mine.Items) != 2 {
		t.Fatal("顺序待办", e)
	}
	f.db.Exec(`UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND role='approver'`, f.c.environment, f.bootstrap.Principals[1].ID)
	mine, e = f.c.SearchRequests(ctx, f.tokens[1], SearchFilter{View: "mine", Limit: 20})
	if e != nil || len(mine.Items) != 0 {
		t.Fatal("撤审批权后仍是待办", e)
	}
	all, e := f.c.SearchRequests(ctx, f.tokens[1], SearchFilter{View: "all", Limit: 1})
	if e != nil || len(all.Items) != 1 || all.Next == "" {
		t.Fatal("保留查看权", e)
	}
	// 仅一次性测试库把后来创建的完整清单放在首游标边界毫秒，模拟并发创建的时间精度边界。
	b, _ := base64.RawURLEncoding.DecodeString(all.Next)
	var p searchPosition
	json.Unmarshal(b, &p)
	// 审批权已经撤销，恢复后创建新申请；只改变当前授权，旧两条依然可按Viewer读取。
	f.db.Exec(`UPDATE keygate.role_grants SET enabled=true WHERE environment=$1 AND principal_id=$2 AND role='approver'`, f.c.environment, f.bootstrap.Principals[1].ID)
	n := submitClient(t, f, "search-late")
	tx, e := f.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	_, m, e := f.c.loadRequest(ctx, tx, n.ID)
	if e != nil {
		t.Fatal(e)
	}
	anchor, _ := time.Parse(time.RFC3339Nano, p.Anchor)
	m.Created = anchor.Format("2006-01-02T15:04:05.000Z")
	m.Expires = anchor.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z")
	raw, _ := manifest.Canonical(m)
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET manifest=$3,digest=$4,expires_at=$5 WHERE environment=$1 AND request_id=$2`, f.c.environment, n.ID, raw, digestBytes(raw), anchor.Add(5*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	next, e := f.c.SearchRequests(ctx, f.tokens[1], SearchFilter{View: "all", Limit: 1, Cursor: all.Next})
	if e != nil || len(next.Items) != 1 || next.Items[0].ID == all.Items[0].ID || next.Items[0].ID == n.ID {
		t.Fatal("同毫秒插入改变已开始的分页", e)
	}
}
