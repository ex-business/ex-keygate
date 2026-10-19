package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"ex-keygate/internal/mfa"
	"time"
)

type MFAAttempt struct {
	Existing                   bool
	ID                         string
	ChallengeID                string
	Factor                     mfa.Factor
	PrincipalID                string
	Nonce                      string
	VerifierCipher, CodeDigest []byte
	ExpiresAt                  time.Time
	LastCounter                int64
}

// BeginMFAFactor 先持久化唯一投递ID和验证摘要；外部发送在事务外执行，失败不删除记录供猜测重试。
func (c *DevelopmentControl) BeginMFAFactor(ctx context.Context, token, challenge, factor, nonce string, cipher, digest []byte, trace string) (MFAAttempt, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return MFAAttempt{}, e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, true)
	if e != nil {
		return MFAAttempt{}, e
	}
	state, e := c.mfaState(ctx, tx, token, a, challenge, false)
	if e != nil {
		return MFAAttempt{}, e
	}
	var selected mfa.Factor
	for _, f := range state.Factors {
		if f.ID == factor {
			selected = f
			break
		}
	}
	if selected.ID == "" || !validNonce(nonce) {
		return MFAAttempt{}, ErrInvalid
	}
	// 先抢占唯一准备记录，再由可信服务端生成并保存验证码保护材料；并发失败者不消耗根预算。
	if len(cipher) > 0 || len(digest) > 0 {
		return MFAAttempt{}, ErrInvalid
	}
	// 页面重载可恢复已就绪的同一项；只读复用原投递ID/nonce，不重新发送验证码或返还次数。
	existing := MFAAttempt{ChallengeID: challenge, Factor: selected, PrincipalID: a.id, Existing: true}
	e = tx.QueryRowContext(ctx, `SELECT attempt_id,nonce,verifier_cipher,code_digest,expires_at FROM keygate.mfa_attempts WHERE environment=$1 AND challenge_id=$2 AND factor_id=$3 AND delivered AND NOT verified AND expires_at>clock_timestamp()`, c.environment, challenge, factor).Scan(&existing.ID, &existing.Nonce, &existing.VerifierCipher, &existing.CodeDigest, &existing.ExpiresAt)
	if e == nil {
		if e = tx.Commit(); e != nil {
			return MFAAttempt{}, e
		}
		return existing, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return MFAAttempt{}, e
	}
	id, e := controlID()
	if e != nil {
		return MFAAttempt{}, e
	}
	attempt := MFAAttempt{ID: id, ChallengeID: challenge, Factor: selected, PrincipalID: a.id, Nonce: nonce, VerifierCipher: cipher, CodeDigest: digest}
	e = tx.QueryRowContext(ctx, `INSERT INTO keygate.mfa_attempts(environment,challenge_id,factor_id,attempt_id,nonce,verifier_cipher,code_digest,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,LEAST($8,clock_timestamp()+interval '2 minutes')) ON CONFLICT DO NOTHING RETURNING expires_at`, c.environment, challenge, factor, id, nonce, cipher, digest, state.ExpiresAt).Scan(&attempt.ExpiresAt)
	if errors.Is(e, sql.ErrNoRows) {
		return attempt, ErrConflict
	}
	if e != nil {
		return attempt, e
	}
	if e = c.audit(ctx, tx, trace, a.id, "mfa_factor_begin", id, "pending"); e != nil {
		return attempt, e
	}
	if e = tx.Commit(); e != nil {
		return MFAAttempt{}, e
	}
	return attempt, nil
}

// SaveMFACode 在对外投递前原子保存HMAC验证材料；每个已抢占attempt只能设置一次。
func (c *DevelopmentControl) SaveMFACode(ctx context.Context, token, challenge, factor, attempt string, cipher, digest []byte, trace string) error {
	if len(cipher) == 0 || len(cipher) > 4096 || len(digest) != 32 {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, true)
	if e != nil {
		return e
	}
	if _, e = c.mfaState(ctx, tx, token, a, challenge, false); e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.mfa_attempts x SET verifier_cipher=$5,code_digest=$6 WHERE x.environment=$1 AND x.challenge_id=$2 AND x.factor_id=$3 AND x.attempt_id=$4 AND NOT x.delivered AND x.verifier_cipher IS NULL AND x.code_digest IS NULL AND x.expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM keygate.mfa_factors f WHERE f.environment=x.environment AND f.principal_id=$7 AND f.factor_id=x.factor_id AND f.method IN ('email','sms'))`, c.environment, challenge, factor, attempt, cipher, digest, a.id)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if e = c.audit(ctx, tx, trace, a.id, "mfa_code_prepare", attempt, "protected"); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *DevelopmentControl) ReadyMFAFactor(ctx context.Context, token, challenge, factor, attempt, trace string) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, true)
	if e != nil {
		return e
	}
	if _, e = c.mfaState(ctx, tx, token, a, challenge, false); e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.mfa_attempts SET delivered=true WHERE environment=$1 AND challenge_id=$2 AND factor_id=$3 AND attempt_id=$4 AND NOT delivered AND expires_at>clock_timestamp() AND (code_digest IS NOT NULL OR EXISTS(SELECT 1 FROM keygate.mfa_factors f WHERE f.environment=keygate.mfa_attempts.environment AND f.principal_id=$5 AND f.factor_id=keygate.mfa_attempts.factor_id AND f.method IN ('totp','hardware')))`, c.environment, challenge, factor, attempt, a.id)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if e = c.audit(ctx, tx, trace, a.id, "mfa_factor_ready", attempt, "ready"); e != nil {
		return e
	}
	return tx.Commit()
}

// ReserveMFAFactor 在核验前提交尝试次数；插件超时、节点崩溃及错误码都不能返还猜测额度。
// 同一绑定的五次/五分钟额度跨会话、申请和节点共享，不因换一个challenge而重置。
func (c *DevelopmentControl) ReserveMFAFactor(ctx context.Context, token, challenge, factor, trace string) (MFAAttempt, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return MFAAttempt{}, e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, true)
	if e != nil {
		return MFAAttempt{}, e
	}
	state, e := c.mfaState(ctx, tx, token, a, challenge, false)
	if e != nil {
		return MFAAttempt{}, e
	}
	attempt := MFAAttempt{ChallengeID: challenge, PrincipalID: a.id}
	for _, f := range state.Factors {
		if f.ID == factor {
			attempt.Factor = f
			break
		}
	}
	if attempt.Factor.ID == "" {
		return attempt, ErrInvalid
	}
	e = tx.QueryRowContext(ctx, `UPDATE keygate.mfa_factors SET tries=CASE WHEN tries_until<=clock_timestamp() THEN 1 ELSE tries+1 END,tries_until=CASE WHEN tries_until<=clock_timestamp() THEN clock_timestamp()+interval '5 minutes' ELSE tries_until END WHERE environment=$1 AND principal_id=$2 AND factor_id=$3 AND (tries_until<=clock_timestamp() OR tries<5) RETURNING last_counter`, c.environment, a.id, factor).Scan(&attempt.LastCounter)
	if errors.Is(e, sql.ErrNoRows) {
		return attempt, ErrDenied
	}
	if e != nil {
		return attempt, e
	}
	e = tx.QueryRowContext(ctx, `UPDATE keygate.mfa_attempts SET tries=tries+1 WHERE environment=$1 AND challenge_id=$2 AND factor_id=$3 AND delivered AND NOT verified AND tries<5 AND expires_at>clock_timestamp() RETURNING attempt_id,nonce,verifier_cipher,code_digest,expires_at`, c.environment, challenge, factor).Scan(&attempt.ID, &attempt.Nonce, &attempt.VerifierCipher, &attempt.CodeDigest, &attempt.ExpiresAt)
	if errors.Is(e, sql.ErrNoRows) {
		return attempt, ErrDenied
	}
	if e != nil {
		return attempt, e
	}
	if e = c.audit(ctx, tx, trace, a.id, "mfa_factor_attempt", attempt.ID, "reserved"); e != nil {
		return attempt, e
	}
	if e = tx.Commit(); e != nil {
		return MFAAttempt{}, e
	}
	return attempt, nil
}

// CompleteMFAFactor 只由服务端验证码/TOTP/硬件插件核验器调用；客户端不能直接提交verified结果。
// 域锁内重新核验会话、人员、策略、当前轮次和期限；撤权/换绑后延迟到达的插件结果无法计票。
func (c *DevelopmentControl) CompleteMFAFactor(ctx context.Context, token string, attempt MFAAttempt, counter int64, verified bool, trace string) (MFAState, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return MFAState{}, e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, true)
	if e != nil {
		return MFAState{}, e
	}
	state, e := c.mfaState(ctx, tx, token, a, attempt.ChallengeID, false)
	if e != nil {
		return state, e
	}
	if !verified {
		if e = c.audit(ctx, tx, trace, a.id, "mfa_factor_verify", attempt.ID, "denied"); e != nil {
			return state, e
		}
		if e = tx.Commit(); e != nil {
			return MFAState{}, e
		}
		return state, ErrDenied
	}
	if attempt.Factor.Method == mfa.TOTP {
		result, e := tx.ExecContext(ctx, `UPDATE keygate.mfa_factors SET last_counter=$4 WHERE environment=$1 AND principal_id=$2 AND factor_id=$3 AND last_counter<$4`, c.environment, a.id, attempt.Factor.ID, counter)
		if e != nil {
			return state, e
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return state, ErrDenied
		}
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.mfa_attempts SET verified=true WHERE environment=$1 AND challenge_id=$2 AND factor_id=$3 AND attempt_id=$4 AND delivered AND NOT verified AND tries>0 AND expires_at>clock_timestamp()`, c.environment, attempt.ChallengeID, attempt.Factor.ID, attempt.ID)
	if e != nil {
		return state, e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return state, ErrDenied
	}
	state.Verified = append(state.Verified, attempt.Factor.ID)
	if state.Policy.Satisfied(state.Factors, state.Verified) {
		h := sha256.Sum256([]byte(token))
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.mfa_proofs(environment,session_hash,purpose,principal_id,principal_revision,policy_revision,verified_at,expires_at) SELECT environment,session_hash,purpose,principal_id,principal_revision,policy_revision,clock_timestamp(),expires_at FROM keygate.mfa_challenges WHERE environment=$1 AND challenge_id=$2 ON CONFLICT(environment,session_hash,purpose) DO UPDATE SET principal_revision=EXCLUDED.principal_revision,policy_revision=EXCLUDED.policy_revision,verified_at=EXCLUDED.verified_at,expires_at=EXCLUDED.expires_at WHERE keygate.mfa_proofs.session_hash=$3`, c.environment, attempt.ChallengeID, h[:]); e != nil {
			return state, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.mfa_challenges SET completed_at=clock_timestamp() WHERE environment=$1 AND challenge_id=$2`, c.environment, attempt.ChallengeID); e != nil {
			return state, e
		}
		state.Completed = true
	}
	if e = c.audit(ctx, tx, trace, a.id, "mfa_factor_verify", attempt.ID, "verified"); e != nil {
		return state, e
	}
	if e = tx.Commit(); e != nil {
		return MFAState{}, e
	}
	c.logger.InfoContext(ctx, "人员二次验证结果已记录", "request_id", trace, "challenge_id", state.ID, "principal_id", a.id, "method", attempt.Factor.Method, "completed", state.Completed, "result", "verified")
	return state, nil
}
