package storage

import (
	"context"
	"errors"
	"ex-keygate/provider"
	"testing"
)

func grantProviderAdmin(t *testing.T, f controlFixture) {
	t.Helper()
	if _, e := f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,'policy_admin','')`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
}
func TestProviderPolicyApprovalsAndOldTickets(t *testing.T) {
	f := newKeyFixture(t)
	ctx := context.Background()
	grantProviderAdmin(t, f.f)
	r := f.issue(t, 1)
	f.stage(t, r)
	cl, _ := f.f.c.Client(ctx, f.f.tokens[0], "one")
	old := submitApproved(t, f.f, ControlOperation{Kind: ActivateKey, ClientID: "one", ExpectedRevision: cl.Revision, KeyVersion: 1})
	if e := f.f.c.DisableProvider(ctx, f.f.tokens[1], "internal-software", unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("审批人越权停用", e)
	}
	if e := f.f.c.DisableProvider(ctx, f.f.tokens[0], "internal-software", unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := f.f.c.ExecuteLocal(ctx, old.ID, old.Digest, unique(t)); e == nil {
		t.Fatal("停用插件旧票执行")
	}
	policies, e := f.f.c.Providers(ctx, f.f.tokens[0])
	if e != nil || len(policies) != 1 {
		t.Fatal(policies, e)
	}
	p := policies[0]
	enable := submitApproved(t, f.f, ControlOperation{Kind: EnableProvider, ClientID: "provider-management", ProviderID: p.ID, ProviderDigest: p.Digest, ExpectedRevision: p.Revision})
	if e = f.f.c.ExecuteLocal(ctx, enable.ID, enable.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = f.f.c.ExecuteLocal(ctx, old.ID, old.Digest, unique(t)); e == nil {
		t.Fatal("重新启用复活旧票")
	}
	f.operation(t, ActivateKey, 1, "")
	if e = f.f.c.RegisterProviderOffline(ctx, provider.HardwareBinding(), unique(t)); e != nil {
		t.Fatal(e)
	}
	policies, e = f.f.c.Providers(ctx, f.f.tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	for _, p = range policies {
		if p.ID != "hardware-reserved" {
			continue
		}
		if _, e = f.f.c.Submit(ctx, f.f.tokens[0], ControlOperation{Kind: EnableProvider, ClientID: "provider-management", ProviderID: p.ID, ProviderDigest: p.Digest, ExpectedRevision: p.Revision}, unique(t), unique(t)); !errors.Is(e, ErrDenied) {
			t.Fatal("硬件预留被启用", e)
		}
	}
}
func TestProviderCheckRejectsLateResults(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	grantProviderAdmin(t, f)
	_, digest, _ := provider.InternalBinding().Encode()
	if _, e := f.c.CheckProvider(ctx, f.tokens[1], "internal-software", digest, unique(t), func(context.Context) (bool, error) { t.Fatal("无权用户触发调用"); return true, nil }); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	_, e := f.c.CheckProvider(ctx, f.tokens[0], "internal-software", digest, unique(t), func(context.Context) (bool, error) {
		if e := f.c.DisableProvider(ctx, f.tokens[0], "internal-software", unique(t)); e != nil {
			t.Fatal(e)
		}
		return true, nil
	})
	if e == nil {
		t.Fatal("停用后接受晚到检查")
	}
	checks, e := f.c.ProviderChecks(ctx, f.tokens[0])
	if e != nil || len(checks) != 0 {
		t.Fatal(checks, e)
	}
}
