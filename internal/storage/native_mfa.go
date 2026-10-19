package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"ex-keygate/internal/mfa"
	"time"
)

func (c *DevelopmentControl) requireNativeMFA(ctx context.Context, tx *sql.Tx, token string, a controlActor) error {
	return c.requireMFAForPurpose(ctx, tx, token, a, "management")
}
func (c *DevelopmentControl) requireMFAForPurpose(ctx context.Context, tx *sql.Tx, token string, a controlActor, purpose string) error {
	var required bool
	if e := tx.QueryRowContext(ctx, `SELECT native_mfa_required FROM keygate.security_domains WHERE environment=$1`, c.environment).Scan(&required); e != nil {
		return e
	}
	if !required {
		return nil
	}
	h := sha256.Sum256([]byte(token))
	var valid bool
	e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.mfa_proofs p JOIN keygate.mfa_policies m USING(environment,principal_id) WHERE p.environment=$1 AND p.session_hash=$2 AND p.purpose=$3 AND p.principal_id=$4 AND p.principal_revision=$5 AND p.policy_revision=m.revision AND p.expires_at>clock_timestamp())`, c.environment, h[:], purpose, a.id, a.revision).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return ErrDenied
	}
	return nil
}

// requireCurrentTurn 严格按冻结清单顺序逐人流转；同一自然人不能在两个位置计票，拒绝不自动跳过。
func (c *DevelopmentControl) requireCurrentTurn(ctx context.Context, tx *sql.Tx, m controlManifest, principal string) error {
	rows, e := tx.QueryContext(ctx, `SELECT principal_id,person_id,principal_revision,grant_revision,grant_scope FROM keygate.control_votes WHERE environment=$1 AND request_id=$2 AND accepted UNION ALL SELECT principal_id,person_id,principal_revision,grant_revision,grant_scope FROM keygate.control_skips WHERE environment=$1 AND request_id=$2`, c.environment, m.RequestID)
	if e != nil {
		return e
	}
	previous := map[string]controlMember{}
	for rows.Next() {
		var member controlMember
		if e = rows.Scan(&member.PrincipalID, &member.PersonID, &member.Revision, &member.GrantRevision, &member.GrantScope); e != nil {
			rows.Close()
			return e
		}
		previous[member.PrincipalID] = member
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	n := len(previous)
	// 已完成的每一位都必须仍是冻结名单中的有效人员，不能在前序撤权后继续交接。
	for i := 0; i < n; i++ {
		if i >= len(m.Approvers) {
			return ErrDenied
		}
		snapshot := m.Approvers[i]
		vote, ok := previous[snapshot.PrincipalID]
		if !ok || vote != snapshot {
			return ErrDenied
		}
		current, e := c.currentMember(ctx, tx, m, snapshot.PrincipalID)
		if e != nil || current != snapshot {
			return ErrDenied
		}
	}

	if n >= len(m.Approvers) || m.Approvers[n].PrincipalID != principal {
		return ErrDenied
	}
	return nil
}

type MFAProvision struct {
	PrincipalID string       `json:"principalId"`
	Policy      mfa.Policy   `json:"policy"`
	Factors     []mfa.Factor `json:"factors"`
}

// ProvisionMFAOffline 只由可信离线工具调用；换绑/丢失恢复必须重新取得两名不同自然人的外部核验记录。
// 不提供“忘记验证码”降级入口；启用后未配置的人员保持拒绝，现有审批清单因人员修订变化失效。
func (c *DevelopmentControl) ProvisionMFAOffline(ctx context.Context, entries []MFAProvision, witnesses [2]string, evidence, trace string) error {
	if len(entries) == 0 || len(entries) > 128 || !validDigest(evidence) || !identifier.MatchString(trace) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT count(DISTINCT person_id) FROM keygate.principals WHERE environment=$1 AND enabled AND principal_id IN($2,$3)`, c.environment, witnesses[0], witnesses[1]).Scan(&count); e != nil {
		return e
	}
	if count != 2 {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if !identifier.MatchString(entry.PrincipalID) || seen[entry.PrincipalID] || entry.Policy.Validate() != nil || len(entry.Factors) == 0 || len(entry.Factors) > 64 {
			return ErrInvalid
		}
		seen[entry.PrincipalID] = true
		counts := map[mfa.Method]int{}
		ids := map[string]bool{}
		fp := map[string]bool{}
		for _, f := range entry.Factors {
			if f.Validate() != nil || ids[f.ID] || fp[f.Fingerprint] {
				return ErrInvalid
			}
			ids[f.ID] = true
			fp[f.Fingerprint] = true
			counts[f.Method]++
		}
		for _, r := range entry.Policy.Rules {
			if counts[r.Method] != r.N {
				return ErrInvalid
			}
			delete(counts, r.Method)
		}
		if len(counts) != 0 {
			return ErrInvalid
		}
		result, e := tx.ExecContext(ctx, `UPDATE keygate.principals SET revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND enabled`, c.environment, entry.PrincipalID)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrDenied
		}
		raw, _ := json.Marshal(entry.Policy)
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.mfa_policies(environment,principal_id,revision,policy) VALUES($1,$2,1,$3) ON CONFLICT(environment,principal_id) DO UPDATE SET revision=keygate.mfa_policies.revision+1,policy=EXCLUDED.policy`, c.environment, entry.PrincipalID, raw); e != nil {
			return e
		}
		// 重新配置同一TOTP种子也不能清除防重放水位，否则旧动态码可借换绑再次使用。
		counters := map[string]int64{}
		rows, e := tx.QueryContext(ctx, `SELECT fingerprint,last_counter FROM keygate.mfa_factors WHERE environment=$1 AND principal_id=$2 AND method='totp'`, c.environment, entry.PrincipalID)
		if e != nil {
			return e
		}
		for rows.Next() {
			var fingerprint string
			var counter int64
			if e = rows.Scan(&fingerprint, &counter); e != nil {
				rows.Close()
				return e
			}
			counters[fingerprint] = counter
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, table := range []string{"mfa_challenges", "mfa_proofs", "mfa_factors"} {
			if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.`+table+` WHERE environment=$1 AND principal_id=$2`, c.environment, entry.PrincipalID); e != nil {
				return e
			}
		}
		for _, f := range entry.Factors {
			last := -int64(1)
			if value, ok := counters[f.Fingerprint]; ok {
				last = value
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.mfa_factors(environment,principal_id,factor_id,method,label,reference,secret_cipher,fingerprint,last_counter) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.environment, entry.PrincipalID, f.ID, f.Method, f.Label, f.Reference, f.SecretCipher, f.Fingerprint, last); e != nil {
				return e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.security_domains SET native_mfa_required=true,revision=revision+1 WHERE environment=$1`, c.environment); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, "offline-bootstrap", "mfa_provision", evidence, "success"); e != nil {
		return e
	}
	return tx.Commit()
}

type MFAState struct {
	ID        string       `json:"id"`
	Purpose   string       `json:"purpose"`
	Policy    mfa.Policy   `json:"policy"`
	Factors   []mfa.Factor `json:"factors"`
	Verified  []string     `json:"verified"`
	Completed bool         `json:"completed"`
	ExpiresAt time.Time    `json:"expiresAt"`
}

func (c *DevelopmentControl) mfaPolicy(ctx context.Context, tx *sql.Tx, principal string) (mfa.Policy, int64, []mfa.Factor, error) {
	var policy mfa.Policy
	var revision int64
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT policy,revision FROM keygate.mfa_policies WHERE environment=$1 AND principal_id=$2`, c.environment, principal).Scan(&raw, &revision)
	if errors.Is(e, sql.ErrNoRows) {
		return policy, 0, nil, ErrDenied
	}
	if e != nil {
		return policy, 0, nil, e
	}
	if json.Unmarshal(raw, &policy) != nil || policy.Validate() != nil {
		return policy, 0, nil, ErrInvalid
	}
	rows, e := tx.QueryContext(ctx, `SELECT factor_id,method,label,reference,secret_cipher,fingerprint FROM keygate.mfa_factors WHERE environment=$1 AND principal_id=$2 ORDER BY factor_id`, c.environment, principal)
	if e != nil {
		return policy, 0, nil, e
	}
	defer rows.Close()
	factors := []mfa.Factor{}
	for rows.Next() {
		var f mfa.Factor
		if e = rows.Scan(&f.ID, &f.Method, &f.Label, &f.Reference, &f.SecretCipher, &f.Fingerprint); e != nil {
			return policy, 0, nil, e
		}
		factors = append(factors, f)
	}
	return policy, revision, factors, rows.Err()
}
func (c *DevelopmentControl) validateMFAPurpose(ctx context.Context, tx *sql.Tx, a controlActor, purpose string) error {
	if purpose == "management" {
		return nil
	}
	if !identifier.MatchString(purpose) {
		return ErrInvalid
	}
	r, m, e := c.loadRequest(ctx, tx, purpose)
	if e != nil {
		return e
	}
	if r.Decision != "pending" || r.Executed {
		return ErrConflict
	}
	if e = c.liveManifest(ctx, tx, m); e != nil {
		return e
	}
	if _, e = c.currentMember(ctx, tx, m, a.id); e != nil {
		return e
	}
	if m.Sequential {
		return c.requireCurrentTurn(ctx, tx, m, a.id)
	}
	return nil
}
func (c *DevelopmentControl) StartMFA(ctx context.Context, token, purpose, trace string) (MFAState, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return MFAState{}, e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, true)
	if e != nil {
		return MFAState{}, e
	}
	if e = c.validateMFAPurpose(ctx, tx, a, purpose); e != nil {
		return MFAState{}, e
	}
	_, rev, _, e := c.mfaPolicy(ctx, tx, a.id)
	if e != nil {
		return MFAState{}, e
	}
	h := sha256.Sum256([]byte(token))
	var id string
	e = tx.QueryRowContext(ctx, `SELECT challenge_id FROM keygate.mfa_challenges WHERE environment=$1 AND session_hash=$2 AND purpose=$3 AND expires_at>clock_timestamp() AND principal_revision=$4 AND policy_revision=$5`, c.environment, h[:], purpose, a.revision, rev).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		var allowed bool
		if e = tx.QueryRowContext(ctx, `SELECT last_started IS NULL OR last_started<=clock_timestamp()-interval '1 second' FROM keygate.mfa_policies WHERE environment=$1 AND principal_id=$2`, c.environment, a.id).Scan(&allowed); e != nil {
			return MFAState{}, e
		}
		if !allowed {
			return MFAState{}, ErrConflict
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.mfa_challenges WHERE environment=$1 AND session_hash=$2 AND purpose=$3`, c.environment, h[:], purpose); e != nil {
			return MFAState{}, e
		}
		id, e = controlID()
		if e != nil {
			return MFAState{}, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.mfa_challenges(environment,challenge_id,principal_id,session_hash,purpose,principal_revision,policy_revision,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,LEAST(s.expires_at,clock_timestamp()+interval '3 minutes') FROM keygate.sessions s WHERE s.token_hash=$4`, c.environment, id, a.id, h[:], purpose, a.revision, rev); e != nil {
			return MFAState{}, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.mfa_policies SET last_started=clock_timestamp() WHERE environment=$1 AND principal_id=$2`, c.environment, a.id); e != nil {
			return MFAState{}, e
		}
		if e = c.audit(ctx, tx, trace, a.id, "mfa_start", id, "pending"); e != nil {
			return MFAState{}, e
		}
	} else if e != nil {
		return MFAState{}, e
	}
	state, e := c.mfaState(ctx, tx, token, a, id, false)
	if e != nil {
		return state, e
	}
	if e = tx.Commit(); e != nil {
		return MFAState{}, e
	}
	return state, nil
}
func (c *DevelopmentControl) mfaState(ctx context.Context, tx *sql.Tx, token string, a controlActor, id string, allowCompleted bool) (MFAState, error) {
	state := MFAState{ID: id, Verified: []string{}}
	h := sha256.Sum256([]byte(token))
	var principalRev, policyRev int64
	var completed sql.NullTime
	e := tx.QueryRowContext(ctx, `SELECT purpose,principal_revision,policy_revision,expires_at,completed_at FROM keygate.mfa_challenges WHERE environment=$1 AND challenge_id=$2 AND principal_id=$3 AND session_hash=$4 AND expires_at>clock_timestamp()`, c.environment, id, a.id, h[:]).Scan(&state.Purpose, &principalRev, &policyRev, &state.ExpiresAt, &completed)
	if errors.Is(e, sql.ErrNoRows) {
		return state, ErrDenied
	}
	if e != nil {
		return state, e
	}
	if principalRev != a.revision {
		return state, ErrDenied
	}
	state.Completed = completed.Valid
	if state.Completed && !allowCompleted {
		return state, ErrConflict
	}
	var current int64
	state.Policy, current, state.Factors, e = c.mfaPolicy(ctx, tx, a.id)
	if e != nil {
		return state, e
	}
	if current != policyRev {
		return state, ErrDenied
	}
	if !state.Completed {
		if e = c.validateMFAPurpose(ctx, tx, a, state.Purpose); e != nil {
			return state, e
		}
	}
	rows, e := tx.QueryContext(ctx, `SELECT factor_id FROM keygate.mfa_attempts WHERE environment=$1 AND challenge_id=$2 AND verified ORDER BY factor_id`, c.environment, id)
	if e != nil {
		return state, e
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return state, e
		}
		state.Verified = append(state.Verified, id)
	}
	return state, rows.Err()
}
func (c *DevelopmentControl) MFAStatus(ctx context.Context, token, id string) (MFAState, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return MFAState{}, e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, true)
	if e != nil {
		return MFAState{}, e
	}
	state, e := c.mfaState(ctx, tx, token, a, id, true)
	if e != nil {
		return state, e
	}
	return state, tx.Commit()
}
