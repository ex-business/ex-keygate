package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"ex-keygate/internal/access"
	"ex-keygate/internal/mfa"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOnlineGovernanceApprovalPermissionsAndSessions(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	if _, e := f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,'policy_admin','')`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	counters := make([]int64, 6)
	complete := func(who int, purpose string) { counters[who]++; completeNative(t, f, who, purpose, counters[who]) }
	complete(0, "management")
	approve := func(op ControlOperation) ControlRequest {
		t.Helper()
		r, e := f.c.Submit(ctx, f.tokens[0], op, unique(t), unique(t))
		if e != nil {
			t.Fatal("submit", e)
		}
		for _, who := range []int{1, 2} {
			complete(who, r.ID)
			if _, e = f.c.Vote(ctx, f.tokens[who], r.ID, r.Digest, true, unique(t)); e != nil {
				t.Fatal("vote", e)
			}
		}
		return r
	}
	execute := func(r ControlRequest) {
		t.Helper()
		if e := f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); e != nil {
			t.Fatal("execute", e)
		}
	}
	makeOp := func(kind string, rev uint64, g GovernanceChange) ControlOperation {
		g.Reason = "组织人员与授权变更"
		g.EvidenceHash = strings.Repeat("e", 64)
		return ControlOperation{Kind: kind, ClientID: "governance-management", ExpectedRevision: rev, Governance: &g}
	}
	create := makeOp(CreatePrincipal, 0, GovernanceChange{Issuer: f.bootstrap.Principals[0].Issuer, Subject: "new-admin", PersonID: "new-person", Enabled: true})
	r, e := f.c.Submit(ctx, f.tokens[0], create, unique(t), unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], r.ID, r.Digest, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("未审批登记人员", e)
	}
	for _, who := range []int{1, 2} {
		complete(who, r.ID)
		if _, e = f.c.Vote(ctx, f.tokens[who], r.ID, r.Digest, true, unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	execute(r)
	expected, _ := access.NewPrincipal(create.Governance.Issuer, create.Governance.Subject, create.Governance.PersonID)
	var grants int
	if e = f.db.QueryRow(`SELECT count(*) FROM keygate.role_grants WHERE environment=$1 AND principal_id=$2`, f.c.environment, expected.ID).Scan(&grants); e != nil || grants != 0 {
		t.Fatal("登记自动授予权限", e)
	}
	if _, e = f.c.Submit(ctx, f.tokens[0], create, unique(t), unique(t)); e == nil {
		t.Fatal("重复登记身份")
	}
	alias := create
	g := *create.Governance
	g.Subject = "other-subject"
	alias.Governance = &g
	if _, e = f.c.Submit(ctx, f.tokens[0], alias, unique(t), unique(t)); e == nil {
		t.Fatal("在线伪造同一自然人别名")
	}
	own := makeOp(UpdatePrincipal, 2, GovernanceChange{Target: f.bootstrap.Principals[0].ID, Enabled: true, Grants: []ConsoleGrant{{Role: access.PolicyAdmin}}})
	if _, e = f.c.Submit(ctx, f.tokens[0], own, unique(t), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("自己修改自己权限", e)
	}
	beneficiary := makeOp(UpdatePrincipal, 2, GovernanceChange{Target: f.bootstrap.Principals[1].ID, Enabled: true, Grants: []ConsoleGrant{{Role: access.Approver}, {Role: access.Viewer}}})
	if _, e = f.c.Submit(ctx, f.tokens[0], beneficiary, unique(t), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("受益审批人给自己投票", e)
	}
	// 为已有范围查看者配置MFA，验证授权变更前可用，变更后旧会话必须重新认证。
	sum := sha256.Sum256([]byte(unique(t)))
	if e = f.c.ProvisionMFAOffline(ctx, []MFAProvision{{PrincipalID: f.bootstrap.Principals[4].ID, Policy: mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: 1, Required: true}}}, Factors: []mfa.Factor{{ID: "otp", Method: mfa.TOTP, Label: "本人验证", SecretCipher: []byte("protected"), Fingerprint: hex.EncodeToString(sum[:])}}}}, f.bootstrap.Witnesses, strings.Repeat("b", 64), unique(t)); e != nil {
		t.Fatal(e)
	}
	complete(4, "management")
	if _, e = f.c.ConsoleIdentity(ctx, f.tokens[4]); e != nil {
		t.Fatal(e)
	}
	update := makeOp(UpdatePrincipal, 2, GovernanceChange{Target: f.bootstrap.Principals[4].ID, Enabled: true, Grants: []ConsoleGrant{{Role: access.Viewer}}})
	// 预先签发auth_time位于未来的旧会话，也必须被明确封禁，不能等时钟追上后复活。
	futureRaw := make([]byte, 32)
	rand.Read(futureRaw)
	futureToken := base64.RawURLEncoding.EncodeToString(futureRaw)
	futureHash := sha256.Sum256([]byte(futureToken))
	if _, e = f.c.store.CreateSession(ctx, futureHash, f.profile, f.bootstrap.Principals[4].ID, time.Now().Add(20*time.Second), Audit{unique(t), unique(t), f.bootstrap.Principals[4].ID, "session_create", hex.EncodeToString(futureHash[:]), "success"}); e != nil {
		t.Fatal(e)
	}
	other, e := NewDevelopmentControl("test", unique(t), f.profile, f.c.store)
	if e != nil {
		t.Fatal(e)
	}
	if e = other.BootstrapOffline(ctx, f.bootstrap, unique(t)); e != nil {
		t.Fatal(e)
	}
	change := approve(update)
	execute(change)
	execute(change)
	if _, e = f.db.Exec(`UPDATE keygate.sessions SET authenticated_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1`, futureHash[:]); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.ConsoleIdentity(ctx, futureToken); !errors.Is(e, ErrDenied) {
		t.Fatal("未来auth_time旧会话复活", e)
	}
	if _, e = other.ConsoleIdentity(ctx, f.tokens[4]); e != nil {
		t.Fatal("污染其他域会话", e)
	}

	if _, e = f.c.ConsoleIdentity(ctx, f.tokens[4]); !errors.Is(e, ErrDenied) {
		t.Fatal("授权变更仍复用旧会话", e)
	}
	if _, e = f.c.Submit(ctx, f.tokens[0], update, unique(t), unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("过期人员修订被接受", e)
	}
	// 新认证不复用旧MFA证明，也不能将普通Requester当策略管理员。
	rawToken := make([]byte, 32)
	rand.Read(rawToken)
	newToken := base64.RawURLEncoding.EncodeToString(rawToken)
	hash := sha256.Sum256([]byte(newToken))
	// 本用例验证撤权与重新认证，避免宿主和容器微小时差误触未来auth_time拒绝分支。
	if _, e = f.c.store.CreateSession(ctx, hash, f.profile, f.bootstrap.Principals[4].ID, time.Now().Add(-time.Second), Audit{unique(t), unique(t), f.bootstrap.Principals[4].ID, "session_create", hex.EncodeToString(hash[:]), "success"}); e != nil {
		t.Fatal(e)
	}
	f.tokens[4] = newToken
	complete(4, "management")
	if _, e = f.c.ConsoleIdentity(ctx, newToken); e != nil {
		t.Fatal("新认证不能访问", e)
	}
	if _, e = f.c.Request(ctx, newToken, r.ID); !errors.Is(e, ErrDenied) {
		t.Fatal("普通Viewer读取组织治理快照", e)
	}
	if _, e = f.c.Submit(ctx, newToken, create, unique(t), unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("非治理人员登记身份", e)
	}
	// 策略管理员被撤权后，旧治理票不能执行；重新授予也不恢复旧冻结资格。
	revoked := approve(makeOp(CreatePrincipal, 0, GovernanceChange{Issuer: create.Governance.Issuer, Subject: "revoked-admin-request", PersonID: "revoked-request-person", Enabled: true}))
	if _, e = f.db.Exec(`UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND role='policy_admin'`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], revoked.ID, revoked.Digest, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("管理员撤权后旧申请执行", e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.role_grants SET enabled=true,revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND role='policy_admin'`, f.c.environment, f.bootstrap.Principals[0].ID); e != nil {
		t.Fatal(e)
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], revoked.ID, revoked.Digest, unique(t)); e == nil {
		t.Fatal("重新授予恢复旧治理资格")
	}
	settings, e := f.c.ConsoleSettings(ctx, f.tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	version, _ := strconv.ParseUint(settings.Version, 10, 64)
	policy := makeOp(UpdateApprovalPolicy, version, GovernanceChange{M: 2, Approvers: []string{f.bootstrap.Principals[2].ID, f.bootstrap.Principals[1].ID}})
	invalid := policy
	bad := *policy.Governance
	bad.M = 1
	invalid.Governance = &bad
	if _, e = f.c.Submit(ctx, f.tokens[0], invalid, unique(t), unique(t)); e == nil {
		t.Fatal("门槛降到一人")
	}
	bad.M = 2
	bad.Approvers = []string{f.bootstrap.Principals[1].ID, f.bootstrap.Principals[3].ID}
	if _, e = f.c.Submit(ctx, f.tokens[0], invalid, unique(t), unique(t)); e == nil {
		t.Fatal("自然人别名重复计人")
	}
	bad.Approvers = []string{f.bootstrap.Principals[0].ID, f.bootstrap.Principals[1].ID}
	if _, e = f.c.Submit(ctx, f.tokens[0], invalid, unique(t), unique(t)); e == nil {
		t.Fatal("移除独立治理发起人")
	}
	// 旧申请已经两人同意，策略更新后仍不得执行旧票。
	old := approve(makeOp(CreatePrincipal, 0, GovernanceChange{Issuer: create.Governance.Issuer, Subject: "pending-old", PersonID: "old-person", Enabled: true}))
	policyRequest := approve(policy)
	execute(policyRequest)
	execute(policyRequest)
	stale, e := f.c.Request(ctx, f.tokens[0], old.ID)
	if e != nil || !stale.Invalidated {
		t.Fatal("旧策略申请未标记失效", e)
	}
	if e = f.c.ExecuteRequested(ctx, f.tokens[0], old.ID, old.Digest, unique(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("旧策略票仍能执行", e)
	}
	settings, e = f.c.ConsoleSettings(ctx, f.tokens[0])
	if e != nil || settings.Approvers[0] != f.bootstrap.Principals[2].ID || settings.Version == strconv.FormatUint(version, 10) {
		t.Fatal("策略未切换", e)
	}
}
