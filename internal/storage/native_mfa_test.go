package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"ex-keygate/internal/mfa"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func nativeFixture(t *testing.T) controlFixture {
	t.Helper()
	f := newControlFixture(t)
	entries := []MFAProvision{}
	for i := 0; i < 3; i++ {
		sum := sha256.Sum256([]byte(unique(t)))
		entries = append(entries, MFAProvision{PrincipalID: f.bootstrap.Principals[i].ID, Policy: mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: 1, Required: true}}}, Factors: []mfa.Factor{{ID: "otp", Method: mfa.TOTP, Label: "动态码", SecretCipher: []byte("opaque-protected-secret"), Fingerprint: hex.EncodeToString(sum[:])}}})
	}
	if e := f.c.ProvisionMFAOffline(context.Background(), entries, f.bootstrap.Witnesses, strings.Repeat("c", 64), unique(t)); e != nil {
		t.Fatal(e)
	}
	if e := f.c.ConfigureSequentialApprovalOffline(context.Background(), f.bootstrap.Approvers, 2, f.bootstrap.Witnesses, strings.Repeat("d", 64), unique(t)); e != nil {
		t.Fatal(e)
	}
	return f
}
func completeNative(t *testing.T, f controlFixture, who int, purpose string, counter int64) MFAState {
	t.Helper()
	ctx := context.Background()
	if _, e := f.db.Exec(`UPDATE keygate.mfa_policies SET last_started=NULL WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	state, e := f.c.StartMFA(ctx, f.tokens[who], purpose, unique(t))
	if e != nil {
		t.Fatal("start", e)
	}
	nonce := make([]byte, 32)
	nonce[0] = byte(counter + 1)
	attempt, e := f.c.BeginMFAFactor(ctx, f.tokens[who], state.ID, "otp", base64.RawURLEncoding.EncodeToString(nonce), nil, nil, unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ReadyMFAFactor(ctx, f.tokens[who], state.ID, "otp", attempt.ID, unique(t)); e != nil {
		t.Fatal(e)
	}
	attempt, e = f.c.ReserveMFAFactor(ctx, f.tokens[who], state.ID, "otp", unique(t))
	if e != nil {
		t.Fatal(e)
	}
	state, e = f.c.CompleteMFAFactor(ctx, f.tokens[who], attempt, counter, true, unique(t))
	if e != nil || !state.Completed {
		t.Fatal("complete", e)
	}
	return state
}
func TestSequentialMofNRequiresEachPersonsOwnRequestProof(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	if _, e := f.c.Profiles(ctx, f.tokens[0]); !errors.Is(e, ErrDenied) {
		t.Fatal("未验证管理身份被放行", e)
	}
	completeNative(t, f, 0, "management", 1)
	request := submitClient(t, f, "native-flow")
	if request.Progress == nil || request.Progress.CurrentPrincipalID != f.bootstrap.Principals[1].ID {
		t.Fatal("没有初始处理人")
	}
	if _, e := f.c.StartMFA(ctx, f.tokens[2], request.ID, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("未轮到的人提前验证", e)
	}
	if _, e := f.c.Vote(ctx, f.tokens[1], request.ID, request.Digest, true, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("未做本人验证就审批", e)
	}
	completeNative(t, f, 1, request.ID, 1)
	otherStore, _ := New(f.db)
	other, _ := NewDevelopmentControl("test", f.c.environment, f.profile, otherStore)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := other.Vote(ctx, f.tokens[1], request.ID, request.Digest, true, unique(t)); e == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("并发交接重复计人", accepted.Load())
	}
	if e := f.c.ExecuteLocal(ctx, request.ID, request.Digest, unique(t)); e == nil {
		t.Fatal("未达到M执行")
	}
	next, e := f.c.loadRequestForTest(ctx, request.ID)
	if e != nil || next.Progress.Completed != 1 || next.Progress.CurrentPrincipalID != f.bootstrap.Principals[2].ID {
		t.Fatal("未交给下一人", e)
	}
	// 上一人的会话和证明无法代替当前人；各人都必须完成自己绑定的验证。
	if _, e := f.c.Vote(ctx, f.tokens[2], request.ID, request.Digest, true, unique(t)); e == nil {
		t.Fatal("下一人借用前序证明")
	}
	completeNative(t, f, 2, request.ID, 1)
	result, e := f.c.Vote(ctx, f.tokens[2], request.ID, request.Digest, true, unique(t))
	if e != nil || result.Decision != "approved" || result.Progress.Completed != 2 {
		t.Fatal("MofN没有完成", e)
	}
	if e = f.c.ExecuteLocal(ctx, request.ID, request.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
}
func (c *DevelopmentControl) loadRequestForTest(ctx context.Context, id string) (ControlRequest, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return ControlRequest{}, e
	}
	defer tx.Rollback()
	r, _, e := c.loadRequest(ctx, tx, id)
	return r, e
}
func TestMFAProofBoundToRequestAndRevocation(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	completeNative(t, f, 0, "management", 1)
	first := submitClient(t, f, "first")
	second := submitClient(t, f, "second")
	completeNative(t, f, 1, first.ID, 1)
	if _, e := f.c.Vote(ctx, f.tokens[1], second.ID, second.Digest, true, unique(t)); !errors.Is(e, ErrDenied) {
		t.Fatal("跨申请复用本人证明", e)
	}
	if _, e := f.c.Vote(ctx, f.tokens[1], first.ID, first.Digest, true, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(`UPDATE keygate.principals SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2`, f.c.environment, f.bootstrap.Principals[1].ID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.c.StartMFA(ctx, f.tokens[2], first.ID, unique(t)); e == nil {
		t.Fatal("前序撤权后仍能交接")
	}
}

func TestExplicitAbstentionDoesNotCountAsApproval(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	completeNative(t, f, 0, "management", 1)
	request := submitClient(t, f, "abstention")
	completeNative(t, f, 1, request.ID, 1)
	result, e := f.c.SkipSequential(ctx, f.tokens[1], request.ID, request.Digest, "本人明确放弃", unique(t))
	if e != nil || result.Decision != "rejected" || result.Progress.Completed != 0 {
		t.Fatal("不足M时放弃被误计为同意", e)
	}
	if e = f.c.ExecuteLocal(ctx, request.ID, request.Digest, unique(t)); e == nil {
		t.Fatal("放弃后执行")
	}
}
func TestMFAAttemptsCannotResetByChangingChallenge(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	state, e := f.c.StartMFA(ctx, f.tokens[0], "management", unique(t))
	if e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, 32)
	nonce[0] = 1
	attempt, e := f.c.BeginMFAFactor(ctx, f.tokens[0], state.ID, "otp", base64.RawURLEncoding.EncodeToString(nonce), nil, nil, unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ReadyMFAFactor(ctx, f.tokens[0], state.ID, "otp", attempt.ID, unique(t)); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if _, e = f.c.ReserveMFAFactor(ctx, f.tokens[0], state.ID, "otp", unique(t)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = f.c.ReserveMFAFactor(ctx, f.tokens[0], state.ID, "otp", unique(t)); e == nil {
		t.Fatal("超额猜测")
	}
	if _, e = f.db.Exec(`UPDATE keygate.mfa_challenges SET expires_at=clock_timestamp()-interval '1 second' WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Exec(`UPDATE keygate.mfa_policies SET last_started=NULL WHERE environment=$1`, f.c.environment); e != nil {
		t.Fatal(e)
	}
	state, e = f.c.StartMFA(ctx, f.tokens[0], "management", unique(t))
	if e != nil {
		t.Fatal(e)
	}
	attempt, e = f.c.BeginMFAFactor(ctx, f.tokens[0], state.ID, "otp", base64.RawURLEncoding.EncodeToString(nonce), nil, nil, unique(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ReadyMFAFactor(ctx, f.tokens[0], state.ID, "otp", attempt.ID, unique(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.ReserveMFAFactor(ctx, f.tokens[0], state.ID, "otp", unique(t)); e == nil {
		t.Fatal("换challenge返还了猜测额度")
	}
}

func TestSequentialTwoOfThreeWithExplicitHandoff(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	third := f.bootstrap.Principals[4]
	if _, e := f.db.Exec(`INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,'approver','')`, f.c.environment, third.ID); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte(unique(t)))
	entry := MFAProvision{PrincipalID: third.ID, Policy: mfa.Policy{M: 1, Rules: []mfa.Rule{{Method: mfa.TOTP, M: 1, N: 1, Required: true}}}, Factors: []mfa.Factor{{ID: "otp", Method: mfa.TOTP, Label: "动态码", SecretCipher: []byte("protected"), Fingerprint: hex.EncodeToString(sum[:])}}}
	if e := f.c.ProvisionMFAOffline(ctx, []MFAProvision{entry}, f.bootstrap.Witnesses, strings.Repeat("c", 64), unique(t)); e != nil {
		t.Fatal(e)
	}
	ids := append(append([]string{}, f.bootstrap.Approvers...), third.ID)
	if e := f.c.ConfigureSequentialApprovalOffline(ctx, ids, 2, f.bootstrap.Witnesses, strings.Repeat("d", 64), unique(t)); e != nil {
		t.Fatal(e)
	}
	completeNative(t, f, 0, "management", 1)
	request := submitClient(t, f, "two-of-three")
	completeNative(t, f, 1, request.ID, 1)
	result, e := f.c.SkipSequential(ctx, f.tokens[1], request.ID, request.Digest, "本人明确放弃", unique(t))
	if e != nil || result.Decision != "pending" || result.Progress.Completed != 0 || result.Progress.Processed != 1 || result.Progress.CurrentPrincipalID != f.bootstrap.Principals[2].ID {
		t.Fatal("放弃未转交或被误计为同意", e)
	}
	completeNative(t, f, 2, request.ID, 1)
	if _, e = f.c.Vote(ctx, f.tokens[2], request.ID, request.Digest, true, unique(t)); e != nil {
		t.Fatal(e)
	}
	if e = f.c.ExecuteLocal(ctx, request.ID, request.Digest, unique(t)); e == nil {
		t.Fatal("一人同意被放行")
	}
	completeNative(t, f, 4, request.ID, 1)
	result, e = f.c.Vote(ctx, f.tokens[4], request.ID, request.Digest, true, unique(t))
	if e != nil || result.Decision != "approved" || result.Progress.Completed != 2 || result.Progress.Processed != 3 {
		t.Fatal("2of3未完成", e)
	}
	if e = f.c.ExecuteLocal(ctx, request.ID, request.Digest, unique(t)); e != nil {
		t.Fatal(e)
	}
}
func TestReprovisionSameTOTPDoesNotResetReplayCounter(t *testing.T) {
	f := nativeFixture(t)
	ctx := context.Background()
	completeNative(t, f, 0, "management", 42)
	policy, _, factors, e := func() (mfa.Policy, int64, []mfa.Factor, error) {
		tx, e := f.c.begin(ctx)
		if e != nil {
			return mfa.Policy{}, 0, nil, e
		}
		defer tx.Rollback()
		return f.c.mfaPolicy(ctx, tx, f.bootstrap.Principals[0].ID)
	}()
	if e != nil {
		t.Fatal(e)
	}
	entry := MFAProvision{PrincipalID: f.bootstrap.Principals[0].ID, Policy: policy, Factors: factors}
	if e = f.c.ProvisionMFAOffline(ctx, []MFAProvision{entry}, f.bootstrap.Witnesses, strings.Repeat("c", 64), unique(t)); e != nil {
		t.Fatal(e)
	}
	var last int64
	if e = f.db.QueryRow(`SELECT last_counter FROM keygate.mfa_factors WHERE environment=$1 AND principal_id=$2`, f.c.environment, entry.PrincipalID).Scan(&last); e != nil || last != 42 {
		t.Fatal("重配置清除了防重放水位", last, e)
	}
	if _, e = f.c.Profiles(ctx, f.tokens[0]); e == nil {
		t.Fatal("重新配置未撤销既有MFA证明")
	}
}
