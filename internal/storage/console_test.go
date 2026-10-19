package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestConsoleIdentityBeforeMFADoesNotExposeBindingSecrets(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	own, e := f.c.ConsoleIdentity(ctx, f.tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	if !own.MFARequired || own.MFAVerified || len(own.Factors) != 1 || own.PrincipalID != f.bootstrap.Principals[0].ID {
		t.Fatal("本人验证入口状态不正确")
	}
	raw, _ := json.Marshal(own)
	for _, field := range []string{"opaque-protected-secret", "secretCipher", "reference", "fingerprint"} {
		if strings.Contains(string(raw), field) {
			t.Fatal("验证说明泄露绑定秘密", field)
		}
	}
	other, e := f.c.ConsoleIdentity(ctx, f.tokens[1])
	if e != nil || other.PrincipalID == own.PrincipalID {
		t.Fatal("不同人员混用说明", e)
	}
	if _, e = f.c.ConsoleSettings(ctx, f.tokens[0]); !errors.Is(e, ErrDenied) {
		t.Fatal("MFA前读取全域设置", e)
	}
}
func TestConsoleSettingsRequireAdministrativeReadScope(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	completeNative(t, f, 0, "management", 1)
	if _, e := f.c.ConsoleSettings(ctx, f.tokens[0]); !errors.Is(e, ErrDenied) {
		t.Fatal("普通全域viewer读取组织权限表", e)
	}
	if _, e := f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,'policy_admin','')`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	out, e := f.c.ConsoleSettings(ctx, f.tokens[0])
	if e != nil || out.M != 2 || !out.Sequential || len(out.People) != 6 || len(out.Approvers) != 2 {
		t.Fatal("策略摘要不正确", e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND role='policy_admin'`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.ConsoleSettings(ctx, f.tokens[0]); !errors.Is(e, ErrDenied) {
		t.Fatal("撤权后仍可读取组织权限表", e)
	}
}
