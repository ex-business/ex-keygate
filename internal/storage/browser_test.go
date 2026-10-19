package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func browserToken(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		t.Fatal(e)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
func browserFixture(t *testing.T) (controlFixture, string) {
	t.Helper()
	f := newControlFixture(t)
	id := unique(t)
	r, e := f.c.Submit(context.Background(), f.tokens[0], ControlOperation{Kind: CreateClient, ClientID: id, Name: "H5", ProfileID: "browser", ProfileVersion: 1}, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	approveControl(t, f, r)
	if e = f.c.ExecuteLocal(context.Background(), r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	return f, id
}
func TestBrowserScopedSessionsDoNotGrantManagement(t *testing.T) {
	f, id := browserFixture(t)
	ctx := context.Background()
	token := browserToken(t)
	// 已登记但没有任何管理角色的人员也可认证；身份认证不会自动变成管理授权。
	session, e := f.c.CreateBrowserSession(ctx, f.tokens[5], id, token, "", 0, unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if session.PrincipalID != f.bootstrap.Principals[5].ID || time.Until(session.ExpiresAt) > 5*time.Minute {
		t.Fatal("身份或期限不正确")
	}
	if _, e = f.c.Clients(ctx, token); !errors.Is(e, ErrDenied) {
		t.Fatal("H5凭据被当成管理会话", e)
	}
	if _, e = f.c.Profiles(ctx, f.tokens[5]); !errors.Is(e, ErrDenied) {
		t.Fatal("认证提升了人员权限", e)
	}
	otherStore, _ := New(f.db)
	other := *f.c
	other.store = otherStore
	if _, e = other.AuthenticateBrowser(ctx, id, token, unique(t)); e != nil {
		t.Fatal("另一实例未共享会话", e)
	}
	if _, e = other.BrowserSession(ctx, "another-client", token); !errors.Is(e, ErrDenied) {
		t.Fatal("跨客户端复用会话", e)
	}
	replacement := browserToken(t)
	if _, e = f.c.CreateBrowserSession(ctx, f.tokens[5], id, replacement, token, 0, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = other.BrowserSession(ctx, id, token); !errors.Is(e, ErrDenied) {
		t.Fatal("轮换后旧Cookie复活", e)
	}
	if e = other.RevokeBrowserSession(ctx, id, replacement, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.AuthenticateBrowser(ctx, id, replacement, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("退出后仍可认证", e)
	}
}
func TestBrowserSessionsRecheckLiveAuthority(t *testing.T) {
	for _, scenario := range []string{"client", "principal", "identity", "expiry", "profile", "client-revision", "principal-revision", "database"} {
		t.Run(scenario, func(t *testing.T) {
			f, id := browserFixture(t)
			ctx := context.Background()
			token := browserToken(t)
			if _, e := f.c.CreateBrowserSession(ctx, f.tokens[5], id, token, "", 0, unique(t)); e != nil {
				t.Fatal(e)
			}
			var e error
			switch scenario {
			case "client":
				e = f.c.EmergencyDisableClient(ctx, f.tokens[0], id, unique(t))
			case "principal":
				_, e = f.db.Exec(`UPDATE keygate.principals SET enabled=false WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[5].ID)
			case "identity":
				_, e = f.db.Exec(`UPDATE keygate.sessions SET revoked_at=clock_timestamp() WHERE principal_id=$1`, f.bootstrap.Principals[5].ID)
			case "expiry":
				_, e = f.db.Exec(`UPDATE keygate.browser_sessions SET expires_at=clock_timestamp()-interval '1 second',authenticated_at=clock_timestamp()-interval '5 minutes' WHERE environment=$1`, f.c.environment)
			case "profile":
				_, e = f.db.Exec(`UPDATE keygate.auth_profiles SET enabled=false WHERE environment=$1 AND profile_id='browser'`, f.c.environment)
			case "client-revision":
				_, e = f.db.Exec(`UPDATE keygate.clients SET revision=revision+1 WHERE environment=$1 AND client_id=$2`, f.c.environment, id)
			case "principal-revision":
				_, e = f.db.Exec(`UPDATE keygate.principals SET revision=revision+1 WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[5].ID)
			case "database":
				e = f.db.Close()
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.c.AuthenticateBrowser(ctx, id, token, unique(t)); e == nil {
				t.Fatal("过期或撤销状态仍放行")
			}
		})
	}
}
func TestBrowserLoginSnapshotAndAuditFailure(t *testing.T) {
	f, id := browserFixture(t)
	ctx := context.Background()
	snapshot, e := f.c.BrowserLoginSnapshot(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.CreateBrowserSession(ctx, f.tokens[5], id, browserToken(t), "", snapshot.Revision+1, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("过期的登录快照仍兑换", e)
	}
	token := browserToken(t)
	if _, e = f.c.CreateBrowserSession(ctx, f.tokens[5], id, token, "", snapshot.Revision, unique(t)); e != nil {
		t.Fatal(e)
	}
	constraint := "browser_fault_" + unique(t)
	if _, e = f.db.Exec(`ALTER TABLE keygate.audit_events ADD CONSTRAINT ` + constraint + ` CHECK(action<>'browser_logout' OR target_id<>'` + id + `')`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e = f.db.Exec(`ALTER TABLE keygate.audit_events DROP CONSTRAINT ` + constraint); e != nil {
			t.Error(e)
		}
	})
	if e = f.c.RevokeBrowserSession(ctx, id, token, unique(t)); e == nil {
		t.Fatal("审计失败仍声称退出成功")
	}
	if _, e = f.c.AuthenticateBrowser(ctx, id, token, unique(t)); e != nil {
		t.Fatal("审计失败未回滚会话撤销", e)
	}
}
