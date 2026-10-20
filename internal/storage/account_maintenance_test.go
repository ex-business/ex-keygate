package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/password"
	"strings"
	"testing"
)

// 已批准的恢复仍须逐项证明新绑定，不能把M阈值当作跳过其余候选的理由。
func TestAccountEnrollmentRequiresAllCandidatesAndConsumesTicket(t *testing.T) {
	f, h := maintenanceFixture(t, 2)
	ctx := context.Background()
	factor := func(id, fp string) mfa.Factor {
		return mfa.Factor{ID: id, Method: mfa.TOTP, Label: "测试验证器", SecretCipher: []byte("reserved"), Fingerprint: strings.Repeat(fp, 64)}
	}
	if e := f.c.CompleteAccountSetup(ctx, h, "", "", unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("缺少绑定仍完成", e)
	}
	for i, id := range []string{"first", "second"} {
		fp := []string{"a", "b"}[i]
		if e := f.c.AddSetupFactor(ctx, h, factor(id, fp), nil, unique(t)); e != nil {
			t.Fatal(e)
		}
		if _, _, e := f.c.SetupFactorAttempt(ctx, h, id, true); !errors.Is(e, ErrDenied) {
			t.Fatal("未准备仍可验证", e)
		}
		if e := f.c.SaveSetupSecrets(ctx, h, id, []byte("protected"), nil); e != nil {
			t.Fatal(e)
		}
		if e := f.c.SaveSetupSecrets(ctx, h, id, []byte("replaced"), nil); !errors.Is(e, ErrConflict) {
			t.Fatal("重复准备重置秘密", e)
		}
		if e := f.c.SetupFactorReady(ctx, h, id); e != nil {
			t.Fatal(e)
		}
		if _, _, e := f.c.SetupFactorAttempt(ctx, h, id, true); e != nil {
			t.Fatal(e)
		}
		if e := f.c.VerifySetupFactor(ctx, h, id, 1, true, unique(t)); e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			if e := f.c.CompleteAccountSetup(ctx, h, "", "", unique(t)); !errors.Is(e, ErrDenied) {
				t.Fatal("M=1绕过第二候选", e)
			}
		}
	}
	if e := f.c.AddSetupFactor(ctx, h, factor("third", "c"), nil, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("超过N仍占用", e)
	}
	if e := f.c.CompleteAccountSetup(ctx, h, "", "", unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e := f.c.AccountSetupStatus(ctx, h); !errors.Is(e, ErrDenied) {
		t.Fatal("一次性票复用", e)
	}
	if _, e := f.c.OwnAccount(ctx, f.tokens[5]); !errors.Is(e, ErrDenied) {
		t.Fatal("旧会话未封禁", e)
	}
	var count int
	if e := f.db.QueryRow(`SELECT count(*) FROM keygate.mfa_factors WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[5].ID).Scan(&count); e != nil || count != 2 {
		t.Fatal(count, e)
	}
}

func maintenanceFixture(t *testing.T, n int) (controlFixture, string) {
	t.Helper()
	f := nativeFixture(t)
	ctx := context.Background()
	if _, e := f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,'policy_admin','')`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	completeNative(t, f, 0, "management", 1)
	h := strings.Repeat("e", 64)
	var revision uint64
	if e := f.db.QueryRow(`SELECT revision FROM keygate.principals WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[5].ID).Scan(&revision); e != nil {
		t.Fatal(e)
	}
	op := ControlOperation{Kind: MaintainAccount, ClientID: "governance-management", ExpectedRevision: revision, Maintenance: &AccountMaintenance{Target: f.bootstrap.Principals[5].ID, Mode: "enroll", TokenHash: h, Policy: &mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: n, Required: true}}}, Reason: "本人首次绑定验证器", EvidenceHash: strings.Repeat("f", 64)}}
	r, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.AccountSetupStatus(ctx, h); !errors.Is(e, ErrDenied) {
		t.Fatal("未执行的票可用", e)
	}
	for _, who := range []int{1, 2} {
		completeNative(t, f, who, r.ID, 1)
		if _, e = f.c.Vote(ctx, f.tokens[who], r.ID, r.Digest, true, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	return f, h
}

func TestAccountSetupQuarantineInvalidatesExecutedTicket(t *testing.T) {
	f, h := maintenanceFixture(t, 1)
	ctx := context.Background()
	if _, e := f.c.AccountSetupStatus(ctx, h); e != nil {
		t.Fatal(e)
	}
	cp, e := f.c.store.CaptureSafetyCheckpoint(ctx, f.c.environment)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.store.QuarantineRestored(ctx, cp, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.AccountSetupStatus(ctx, h); !errors.Is(e, ErrDenied) {
		t.Fatal("恢复后票仍有效", e)
	}
	var consumed bool
	if e = f.db.QueryRow(`SELECT consumed FROM keygate.account_setups WHERE environment=$1 AND token_hash=$2`, f.c.environment, h).Scan(&consumed); e != nil || !consumed {
		t.Fatal(consumed, e)
	}
}

func TestAccountSetupVerificationBudgetCannotReset(t *testing.T) {
	f, h := maintenanceFixture(t, 1)
	ctx := context.Background()
	v := mfa.Factor{ID: "candidate", Method: mfa.TOTP, Label: "本人验证器", SecretCipher: []byte("reserved"), Fingerprint: strings.Repeat("a", 64)}
	if e := f.c.AddSetupFactor(ctx, h, v, nil, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := f.c.SaveSetupSecrets(ctx, h, v.ID, []byte("protected"), nil); e != nil {
		t.Fatal(e)
	}
	if e := f.c.SetupFactorReady(ctx, h, v.ID); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if _, _, e := f.c.SetupFactorAttempt(ctx, h, v.ID, true); e != nil {
			t.Fatal(e)
		}
		if e := f.c.VerifySetupFactor(ctx, h, v.ID, 0, false, unique(t)); !errors.Is(e, ErrDenied) {
			t.Fatal(e)
		}
	}
	if _, _, e := f.c.SetupFactorAttempt(ctx, h, v.ID, true); !errors.Is(e, ErrDenied) {
		t.Fatal("预算超限", e)
	}
	if e := f.c.AddSetupFactor(ctx, h, v, nil, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("重复候选重置预算", e)
	}
}

func TestOwnPasswordChangeChecksSnapshotAndRevokesSession(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	old := "disposable-old-password-123"
	next := "disposable-new-password-456"
	encoded, e := password.Hash(old)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ProvisionLocalAccountsOffline(ctx, []LocalAccount{{Username: "owner", PrincipalID: f.bootstrap.Principals[0].ID, PasswordHash: encoded}}, unique(t)); e != nil {
		t.Fatal(e)
	}
	completeNative(t, f, 0, "management", 1)
	snapshot, e := f.c.PasswordChangeSnapshot(ctx, f.tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	newHash, e := password.Hash(next)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ChangeOwnPassword(ctx, f.tokens[0], snapshot, false, newHash, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("旧密码错误仍更新", e)
	}
	stale := snapshot
	stale.Revision++
	if e = f.c.ChangeOwnPassword(ctx, f.tokens[0], stale, true, newHash, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("过期快照更新", e)
	}
	if e = f.c.ChangeOwnPassword(ctx, f.tokens[0], snapshot, true, newHash, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.OwnAccount(ctx, f.tokens[0]); !errors.Is(e, ErrDenied) {
		t.Fatal("修改密码未封禁旧会话", e)
	}
	login := func(value string) error {
		h := sha256.Sum256([]byte(browserToken(t)))
		_, e := f.c.PasswordSession(ctx, "owner", value, h, [32]byte{}, unique(t))
		return e
	}
	if e = login(old); e == nil {
		t.Fatal("旧密码仍有效", e)
	}
	if e = login(next); e != nil {
		t.Fatal("新密码不能登录", e)
	}
}

func TestAccountRecoveryCannotRetainLostFactorAndBindRequiresOwner(t *testing.T) {
	f, h := maintenanceFixture(t, 1)
	ctx := context.Background()
	candidate := mfa.Factor{ID: "otp", Method: mfa.TOTP, Label: "原验证器", SecretCipher: []byte("reserved"), Fingerprint: strings.Repeat("a", 64)}
	if e := f.c.AddSetupFactor(ctx, h, candidate, nil, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := f.c.SaveSetupSecrets(ctx, h, candidate.ID, []byte("protected"), nil); e != nil {
		t.Fatal(e)
	}
	if e := f.c.SetupFactorReady(ctx, h, candidate.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e := f.c.SetupFactorAttempt(ctx, h, candidate.ID, true); e != nil {
		t.Fatal(e)
	}
	if e := f.c.VerifySetupFactor(ctx, h, candidate.ID, 1, true, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := f.c.CompleteAccountSetup(ctx, h, "", "", unique(t)); e != nil {
		t.Fatal(e)
	}
	policy := mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: 1, Required: true}}}
	var revision uint64
	if e := f.db.QueryRow(`SELECT revision FROM keygate.principals WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[5].ID).Scan(&revision); e != nil {
		t.Fatal(e)
	}
	plan := &AccountMaintenance{Target: f.bootstrap.Principals[5].ID, Mode: "recover", TokenHash: strings.Repeat("d", 64), Policy: &policy, PreviousPolicy: &policy, Keep: []string{"otp"}, Reason: "验证器丢失后受控恢复", EvidenceHash: strings.Repeat("b", 64)}
	op := ControlOperation{Kind: MaintainAccount, ClientID: "governance-management", ExpectedRevision: revision, Maintenance: plan}
	if _, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t)); !errors.Is(e, ErrInvalid) {
		t.Fatal("丢失恢复保留旧绑定", e)
	}
	plan.Mode = "bind"
	r, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, who := range []int{1, 2} {
		completeNative(t, f, who, r.ID, 2)
		if _, e = f.c.Vote(ctx, f.tokens[who], r.ID, r.Digest, true, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = f.c.CompleteAccountSetup(ctx, plan.TokenHash, f.tokens[0], "", unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("管理员代替本人换绑", e)
	}
	if e = f.c.CompleteAccountSetup(ctx, plan.TokenHash, f.tokens[5], "", unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("旧目标会话换绑", e)
	}
	// 即使票已执行，申请人的授权撤销也必须立即封禁后续设置。
	if _, e = f.db.Exec(`DELETE FROM keygate.role_grants WHERE environment=$1 AND principal_id=$2 AND role='policy_admin'`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.AccountSetupStatus(ctx, plan.TokenHash); !errors.Is(e, ErrDenied) {
		t.Fatal("撤权后设置票仍有效", e)
	}
}

func TestApprovedLossRecoveryReplacesOldFactorWithoutOldSession(t *testing.T) {
	f, h := maintenanceFixture(t, 1)
	ctx := context.Background()
	prove := func(hash, id, fp string) {
		t.Helper()
		v := mfa.Factor{ID: id, Method: mfa.TOTP, Label: "恢复验证器", SecretCipher: []byte("reserved"), Fingerprint: strings.Repeat(fp, 64)}
		if e := f.c.AddSetupFactor(ctx, hash, v, nil, unique(t)); e != nil {
			t.Fatal(e)
		}
		if e := f.c.SaveSetupSecrets(ctx, hash, id, []byte("protected"), nil); e != nil {
			t.Fatal(e)
		}
		if e := f.c.SetupFactorReady(ctx, hash, id); e != nil {
			t.Fatal(e)
		}
		if _, _, e := f.c.SetupFactorAttempt(ctx, hash, id, true); e != nil {
			t.Fatal(e)
		}
		if e := f.c.VerifySetupFactor(ctx, hash, id, 1, true, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	prove(h, "lost", "a")
	if e := f.c.CompleteAccountSetup(ctx, h, "", "", unique(t)); e != nil {
		t.Fatal(e)
	}
	policy := mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: 1, Required: true}}}
	var revision uint64
	if e := f.db.QueryRow(`SELECT revision FROM keygate.principals WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[5].ID).Scan(&revision); e != nil {
		t.Fatal(e)
	}
	hash := strings.Repeat("d", 64)
	op := ControlOperation{Kind: MaintainAccount, ClientID: "governance-management", ExpectedRevision: revision, Maintenance: &AccountMaintenance{Target: f.bootstrap.Principals[5].ID, Mode: "recover", TokenHash: hash, Policy: &policy, PreviousPolicy: &policy, Reason: "设备丢失且核验本人恢复", EvidenceHash: strings.Repeat("b", 64)}}
	r, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, who := range []int{1, 2} {
		completeNative(t, f, who, r.ID, 2)
		if _, e = f.c.Vote(ctx, f.tokens[who], r.ID, r.Digest, true, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
	prove(hash, "replacement", "c")
	// 真正丢失设备时无旧会话；恢复只能依靠独立审批票及全部新绑定证明。
	if e = f.c.CompleteAccountSetup(ctx, hash, "", "", unique(t)); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = f.db.QueryRow(`SELECT count(*) FROM keygate.mfa_factors WHERE environment=$1 AND principal_id=$2 AND factor_id='lost'`, f.c.environment, f.bootstrap.Principals[5].ID).Scan(&count); e != nil || count != 0 {
		t.Fatal("丢失旧绑定仍保留", e)
	}
	if _, e = f.c.AccountSetupStatus(ctx, hash); !errors.Is(e, ErrDenied) {
		t.Fatal("恢复票复用", e)
	}
}
