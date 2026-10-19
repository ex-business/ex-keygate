package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"ex-keygate/internal/password"
	"sync"
	"testing"
)

func TestLocalPasswordSessionAndSharedBudget(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	encoded, e := password.Hash("test-local-secret-123456")
	if e != nil {
		t.Fatal(e)
	}
	accounts := []LocalAccount{{Username: "operator", PrincipalID: f.bootstrap.Principals[0].ID, PasswordHash: encoded}}
	for i := 0; i < 2; i++ {
		if e = f.c.ProvisionLocalAccountsOffline(ctx, accounts, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	login := func(c *DevelopmentControl, value string, previous [32]byte) (string, error) {
		token := browserToken(t)
		h := sha256.Sum256([]byte(token))
		_, e := c.PasswordSession(ctx, "operator", value, h, previous, unique(t))
		return token, e
	}
	token, e := login(f.c, "test-local-secret-123456", [32]byte{})
	if e != nil {
		t.Fatal(e)
	}
	own, e := f.c.ConsoleIdentity(ctx, token)
	if e != nil || own.MFAVerified || !own.MFARequired {
		t.Fatal("口令阶段错误地获得MFA权限", e)
	}
	if _, e = f.db.Exec(`INSERT INTO keygate.clients(environment,client_id,name,client_type,profile_id,profile_version,state) VALUES($1,'local-h5','H5','browser','browser',1,'enabled')`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.CreateBrowserSession(ctx, token, "local-h5", browserToken(t), "", 0, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("密码阶段绕过MFA兑换H5", e)
	}
	f.tokens[0] = token
	completeNative(t, f, 0, "management", 1)
	browser := browserToken(t)
	if _, e = f.c.CreateBrowserSession(ctx, token, "local-h5", browser, "", 0, unique(t)); e != nil {
		t.Fatal("完整验证不能兑换H5", e)
	}
	if _, e = f.c.AuthenticateBrowser(ctx, "local-h5", browser, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Exec(`DELETE FROM keygate.mfa_proofs WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.AuthenticateBrowser(ctx, "local-h5", browser, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("MFA证明失效后H5仍认证成功", e)
	}

	if _, e = f.c.Profiles(ctx, token); !errors.Is(e, ErrDenied) {
		t.Fatal("未完成MFA已获业务权限", e)
	}
	next, e := login(f.c, "test-local-secret-123456", sha256.Sum256([]byte(token)))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.store.Session(ctx, sha256.Sum256([]byte(token)), f.c.profile); !errors.Is(e, ErrSession) {
		t.Fatal("旧会话未撤销", e)
	}
	if _, e = f.c.store.Session(ctx, sha256.Sum256([]byte(next)), f.c.profile); e != nil {
		t.Fatal(e)
	}
	node, _ := NewDevelopmentControl("test", f.c.environment, f.c.profile, f.c.store)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := f.c
			if i%2 == 1 {
				c = node
			}
			if _, e := login(c, "wrong-password", [32]byte{}); !errors.Is(e, ErrCredentials) {
				t.Error("错误密码未被拒绝", e)
			}
		}(i)
	}
	wg.Wait()
	if _, e = login(f.c, "test-local-secret-123456", [32]byte{}); !errors.Is(e, ErrCredentials) {
		t.Fatal("锁定期内登录成功", e)
	}
	var failures int
	if e = f.db.QueryRow(`SELECT failures FROM keygate.local_accounts WHERE environment=$1`, f.c.environment).Scan(&failures); e != nil || failures != 5 {
		t.Fatal("多节点失败计数错误", e, failures)
	}
	if _, e = f.db.Exec(`UPDATE keygate.local_accounts SET locked_until=clock_timestamp()-interval '1 second' WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	if _, e = login(f.c, "test-local-secret-123456", [32]byte{}); e != nil {
		t.Fatal("锁定到期不能登录", e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.local_login_budget SET attempts=60 WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	if _, e = login(node, "test-local-secret-123456", [32]byte{}); !errors.Is(e, ErrCredentials) {
		t.Fatal("共享预算未生效", e)
	}
}
func TestLocalAccountRequiresMFA(t *testing.T) {
	f := newControlFixture(t)
	encoded, _ := password.Hash("test-local-secret-123456")
	if e := f.c.ProvisionLocalAccountsOffline(context.Background(), []LocalAccount{{"operator", f.bootstrap.Principals[0].ID, encoded}}, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("无MFA人员可启用本地密码", e)
	}
}
