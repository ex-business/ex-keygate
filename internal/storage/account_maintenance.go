package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"ex-keygate/internal/access"
	"ex-keygate/internal/mfa"
	"ex-keygate/internal/password"
	"slices"
	"time"
)

const MaintainAccount = "account_maintenance"

type AccountMaintenance struct {
	Target         string      `json:"target"`
	Mode           string      `json:"mode"`
	TokenHash      string      `json:"tokenHash,omitempty"`
	Username       string      `json:"username,omitempty"`
	ResetPassword  bool        `json:"resetPassword"`
	Enabled        bool        `json:"enabled"`
	Unlock         bool        `json:"unlock"`
	PreviousPolicy *mfa.Policy `json:"previousPolicy,omitempty"`
	Policy         *mfa.Policy `json:"policy,omitempty"`
	Keep           []string    `json:"keep,omitempty"`
	Reason         string      `json:"reason"`
	EvidenceHash   string      `json:"evidenceHash"`
}
type AccountInfo struct {
	Username string `json:"username"`
	Enabled  bool   `json:"enabled"`
	Locked   bool   `json:"locked"`
	Revision string `json:"revision"`
}

func (c *DevelopmentControl) accountInfo(ctx context.Context, tx *sql.Tx, target string) (*AccountInfo, error) {
	var v AccountInfo
	e := tx.QueryRowContext(ctx, `SELECT username,enabled,locked_until>clock_timestamp(),revision::text FROM keygate.local_accounts WHERE environment=$1 AND principal_id=$2`, c.environment, target).Scan(&v.Username, &v.Enabled, &v.Locked, &v.Revision)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return &v, e
}
func (c *DevelopmentControl) validateAccountMaintenance(ctx context.Context, tx *sql.Tx, op ControlOperation) error {
	p := op.Maintenance
	if p == nil || op.ClientID != "governance-management" || !access.ValidID(p.Target) || !validGovernanceReason(p.Reason) || !validDigest(p.EvidenceHash) {
		return ErrInvalid
	}
	copy := op
	copy.Maintenance = nil
	copy.Kind = ""
	copy.ClientID = ""
	copy.ExpectedRevision = 0
	raw, _ := json.Marshal(copy)
	zero, _ := json.Marshal(ControlOperation{})
	if !bytes.Equal(raw, zero) {
		return ErrInvalid
	}
	var revision uint64
	var active, native bool
	if e := tx.QueryRowContext(ctx, `SELECT p.revision,p.enabled,d.native_mfa_required FROM keygate.principals p JOIN keygate.security_domains d USING(environment) WHERE p.environment=$1 AND p.principal_id=$2`, c.environment, p.Target).Scan(&revision, &active, &native); e != nil {
		return e
	}
	if revision != op.ExpectedRevision {
		return ErrConflict
	}
	if !active || !native {
		return ErrDenied
	}
	account, e := c.accountInfo(ctx, tx, p.Target)
	if e != nil {
		return e
	}
	if p.Mode == "account_state" {
		if account == nil || p.PreviousPolicy != nil || p.Policy != nil || len(p.Keep) != 0 || p.TokenHash != "" || p.ResetPassword || p.Username != "" {
			return ErrInvalid
		}
		return nil
	}
	if p.Mode != "bind" && p.Mode != "recover" && p.Mode != "enroll" {
		return ErrInvalid
	}
	if !validDigest(p.TokenHash) || p.Policy == nil || p.Policy.Validate() != nil || p.Unlock || p.Enabled {
		return ErrInvalid
	}
	if p.Mode == "recover" && len(p.Keep) != 0 {
		return ErrInvalid
	}
	if p.ResetPassword {
		if !accountName.MatchString(p.Username) || (account != nil && account.Username != p.Username) {
			return ErrInvalid
		}
		var exists bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.local_accounts WHERE environment=$1 AND username=$2 AND principal_id<>$3)`, c.environment, p.Username, p.Target).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return ErrConflict
		}
	} else if p.Username != "" {
		return ErrInvalid
	}
	old, _, factors, e := c.mfaPolicy(ctx, tx, p.Target)
	ready := e == nil
	if e != nil && !errors.Is(e, ErrDenied) {
		return e
	}
	if p.Mode == "enroll" && (ready || len(p.Keep) != 0) {
		return ErrConflict
	}
	if p.Mode == "bind" && !ready {
		return ErrConflict
	}
	if ready {
		if p.PreviousPolicy == nil || p.PreviousPolicy.Digest() != old.Digest() {
			return ErrConflict
		}
	} else if p.PreviousPolicy != nil {
		return ErrInvalid
	}
	counts := map[mfa.Method]int{}
	seen := map[string]bool{}
	for _, id := range p.Keep {
		if seen[id] {
			return ErrInvalid
		}
		seen[id] = true
		found := false
		for _, f := range factors {
			if f.ID == id {
				counts[f.Method]++
				found = true
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	total := 0
	for _, rule := range p.Policy.Rules {
		if counts[rule.Method] > rule.N {
			return ErrInvalid
		}
		total += rule.N
		delete(counts, rule.Method)
	}
	if total > 64 || len(counts) != 0 {
		return ErrInvalid
	}
	return nil
}
func (c *DevelopmentControl) applyAccountMaintenance(ctx context.Context, tx *sql.Tx, op ControlOperation, approval, actor, trace string) error {
	p := op.Maintenance
	if p.Mode == "account_state" {
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.local_accounts SET enabled=$3,revision=revision+1,failures=CASE WHEN $4 THEN 0 ELSE failures END,locked_until=CASE WHEN $4 THEN '-infinity'::timestamptz ELSE locked_until END WHERE environment=$1 AND principal_id=$2`, c.environment, p.Target, p.Enabled, p.Unlock); e != nil {
			return e
		}
		if e := c.invalidateAccountSessions(ctx, tx, p.Target); e != nil {
			return e
		}
	} else {
		if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.account_setups(environment,setup_id,target,token_hash,request_id,expires_at) SELECT environment,request_id,$3,$4,request_id,LEAST(expires_at,clock_timestamp()+interval '10 minutes') FROM keygate.control_requests WHERE environment=$1 AND request_id=$2`, c.environment, approval, p.Target, p.TokenHash); e != nil {
			return e
		}
	}
	return c.audit(ctx, tx, trace, actor, "account_maintenance", p.Target, "approved")
}

// invalidateAccountSessions 同事务增加人员修订并封禁当前域已有Cookie，不能让旧验证证明、旧票或H5会话继续使用。
func (c *DevelopmentControl) invalidateAccountSessions(ctx context.Context, tx *sql.Tx, target string) error {
	if _, e := tx.ExecContext(ctx, `UPDATE keygate.principals SET revision=revision+1 WHERE environment=$1 AND principal_id=$2`, c.environment, target); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO keygate.principal_session_blocks(environment,token_hash) SELECT $1,token_hash FROM keygate.sessions WHERE principal_id=$2 AND profile_hash=$3 ON CONFLICT DO NOTHING`, c.environment, target, c.profile)
	return e
}

type AccountSetup struct {
	ID            string       `json:"id"`
	Target        string       `json:"target"`
	PersonID      string       `json:"personId"`
	Mode          string       `json:"mode"`
	Policy        mfa.Policy   `json:"policy"`
	Keep          []mfa.Factor `json:"keep"`
	Factors       []mfa.Factor `json:"factors"`
	Verified      []string     `json:"verified"`
	ResetPassword bool         `json:"resetPassword"`
	Username      string       `json:"username"`
	ExpiresAt     time.Time    `json:"expiresAt"`
}

// setupRead 每次检查当前审批资格、人员修订和有效期；已批准票不等于永久有效的恢复授权。
func (c *DevelopmentControl) setupRead(ctx context.Context, tx *sql.Tx, tokenHash string) (AccountSetup, controlManifest, error) {
	var out AccountSetup
	var request string
	if !validDigest(tokenHash) {
		return out, controlManifest{}, ErrDenied
	}
	e := tx.QueryRowContext(ctx, `SELECT s.setup_id,s.target,s.request_id,p.person_id,s.expires_at FROM keygate.account_setups s JOIN keygate.principals p ON p.environment=s.environment AND p.principal_id=s.target WHERE s.environment=$1 AND s.token_hash=$2 AND NOT s.consumed AND s.expires_at>clock_timestamp() AND p.enabled FOR UPDATE OF s`, c.environment, tokenHash).Scan(&out.ID, &out.Target, &request, &out.PersonID, &out.ExpiresAt)
	if e != nil {
		return out, controlManifest{}, ErrDenied
	}
	r, manifest, e := c.loadRequest(ctx, tx, request)
	if e != nil {
		return out, manifest, e
	}
	if !r.Executed || manifest.Operation.Kind != MaintainAccount {
		return out, manifest, ErrDenied
	}
	if e = c.liveManifest(ctx, tx, manifest); e != nil {
		return out, manifest, e
	}
	if e = c.verifyVotes(ctx, tx, manifest); e != nil {
		return out, manifest, e
	}
	if e = c.validateAccountMaintenance(ctx, tx, manifest.Operation); e != nil {
		return out, manifest, e
	}
	p := manifest.Operation.Maintenance
	out.Mode = p.Mode
	out.Policy = *p.Policy
	out.ResetPassword = p.ResetPassword
	out.Username = p.Username
	out.Keep = []mfa.Factor{}
	out.Factors = []mfa.Factor{}
	out.Verified = []string{}
	_, _, old, _ := c.mfaPolicy(ctx, tx, out.Target)
	for _, f := range old {
		if slices.Contains(p.Keep, f.ID) {
			out.Keep = append(out.Keep, f)
		}
	}
	rows, e := tx.QueryContext(ctx, `SELECT factor_id,method,label,verified FROM keygate.account_setup_factors WHERE environment=$1 AND setup_id=$2 ORDER BY factor_id`, c.environment, out.ID)
	if e != nil {
		return out, manifest, e
	}
	for rows.Next() {
		var f mfa.Factor
		var verified bool
		if e = rows.Scan(&f.ID, &f.Method, &f.Label, &verified); e != nil {
			rows.Close()
			return out, manifest, e
		}
		out.Factors = append(out.Factors, f)
		if verified {
			out.Verified = append(out.Verified, f.ID)
		}
	}
	e = rows.Err()
	rows.Close()
	return out, manifest, e
}
func (c *DevelopmentControl) AccountSetupStatus(ctx context.Context, tokenHash string) (AccountSetup, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return AccountSetup{}, e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, tokenHash)
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}

// AddSetupFactor 候选不计入当前登录因素，服务端约束已批准N和唯一指纹，不能不断重建挑战增加猜测额度。
func (c *DevelopmentControl) AddSetupFactor(ctx context.Context, tokenHash string, f mfa.Factor, verifier []byte, trace string) error {
	if f.Validate() != nil || !access.ValidID(trace) || len(verifier) > 4096 {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, tokenHash)
	if e != nil {
		return e
	}
	counts := map[mfa.Method]int{}
	for _, old := range append(append([]mfa.Factor{}, out.Keep...), out.Factors...) {
		counts[old.Method]++
		if old.ID == f.ID {
			return ErrConflict
		}
	}
	allowed := false
	for _, rule := range out.Policy.Rules {
		if rule.Method == f.Method && counts[f.Method] < rule.N {
			allowed = true
		}
	}
	if !allowed {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.account_setup_factors(environment,setup_id,factor_id,method,label,reference,secret_cipher,fingerprint,verifier_cipher) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.environment, out.ID, f.ID, f.Method, f.Label, f.Reference, f.SecretCipher, f.Fingerprint, verifier); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, out.Target, "account_setup_factor", out.Target, "prepared"); e != nil {
		return e
	}
	return tx.Commit()
}

type SetupAttempt struct {
	SetupID, Target string
	Factor          mfa.Factor
	Verifier        []byte
	LastCounter     int64
	Delivered       bool
}

func (c *DevelopmentControl) SetupFactorAttempt(ctx context.Context, tokenHash, id string, reserve bool) (SetupAttempt, time.Time, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return SetupAttempt{}, time.Time{}, e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, tokenHash)
	if e != nil {
		return SetupAttempt{}, time.Time{}, e
	}
	v := SetupAttempt{SetupID: out.ID, Target: out.Target}
	if reserve {
		result, e := tx.ExecContext(ctx, `UPDATE keygate.account_setup_factors SET tries=tries+1 WHERE environment=$1 AND setup_id=$2 AND factor_id=$3 AND prepared AND NOT verified AND delivered AND tries<5`, c.environment, out.ID, id)
		if e != nil {
			return v, time.Time{}, e
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return v, time.Time{}, ErrDenied
		}
	}
	e = tx.QueryRowContext(ctx, `SELECT factor_id,method,label,reference,secret_cipher,fingerprint,verifier_cipher,last_counter,delivered FROM keygate.account_setup_factors WHERE environment=$1 AND setup_id=$2 AND factor_id=$3 AND prepared AND NOT verified`, c.environment, out.ID, id).Scan(&v.Factor.ID, &v.Factor.Method, &v.Factor.Label, &v.Factor.Reference, &v.Factor.SecretCipher, &v.Factor.Fingerprint, &v.Verifier, &v.LastCounter, &v.Delivered)
	if e != nil {
		return v, time.Time{}, ErrDenied
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return v, now, e
	}
	return v, now, tx.Commit()
}
func (c *DevelopmentControl) SetupFactorReady(ctx context.Context, tokenHash, id string) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, tokenHash)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.account_setup_factors SET delivered=true WHERE prepared AND environment=$1 AND setup_id=$2 AND factor_id=$3`, c.environment, out.ID, id); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *DevelopmentControl) VerifySetupFactor(ctx context.Context, tokenHash, id string, counter int64, valid bool, trace string) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, tokenHash)
	if e != nil {
		return e
	}
	if !valid {
		if e = c.audit(ctx, tx, trace, out.Target, "account_setup_verify", out.Target, "denied"); e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		return ErrDenied
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.account_setup_factors SET verified=true,last_counter=$4 WHERE environment=$1 AND setup_id=$2 AND factor_id=$3 AND NOT verified AND delivered AND tries>0`, c.environment, out.ID, id, counter)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if e = c.audit(ctx, tx, trace, out.Target, "account_setup_verify", out.Target, "verified"); e != nil {
		return e
	}
	return tx.Commit()
}

// CompleteAccountSetup 先证明新绑定，再原子替换策略/凭据并封禁旧会话；任意审计或并发冲突整体回滚。
func (c *DevelopmentControl) CompleteAccountSetup(ctx context.Context, tokenHash, ownerToken, newHash, trace string) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, tokenHash)
	if e != nil {
		return e
	}
	if out.Mode == "bind" {
		a, e := c.actor(ctx, tx, ownerToken, true)
		if e != nil {
			return e
		}
		if a.id != out.Target {
			return ErrDenied
		}
	}
	if out.ResetPassword {
		if _, _, e = password.Parse(newHash); e != nil {
			return ErrInvalid
		}
	} else if newHash != "" {
		return ErrInvalid
	}
	counts := map[mfa.Method]int{}
	for _, f := range out.Keep {
		counts[f.Method]++
	}
	if len(out.Factors) != len(out.Verified) {
		return ErrDenied
	}
	for _, f := range out.Factors {
		counts[f.Method]++
	}
	for _, rule := range out.Policy.Rules {
		if counts[rule.Method] != rule.N {
			return ErrDenied
		}
		delete(counts, rule.Method)
	}
	if len(counts) != 0 {
		return ErrInvalid
	}
	// 保留项的TOTP计数和跨会话猜测预算保持原值，换绑不得重置旧绑定额度。
	keep := out.Keep
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.mfa_challenges WHERE environment=$1 AND principal_id=$2`, c.environment, out.Target); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.mfa_proofs WHERE environment=$1 AND principal_id=$2`, c.environment, out.Target); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.mfa_factors WHERE environment=$1 AND principal_id=$2 AND NOT(factor_id=ANY($3))`, c.environment, out.Target, factorIDs(keep)); e != nil {
		return e
	}
	raw, _ := json.Marshal(out.Policy)
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.mfa_policies(environment,principal_id,revision,policy) VALUES($1,$2,1,$3) ON CONFLICT(environment,principal_id) DO UPDATE SET revision=mfa_policies.revision+1,policy=EXCLUDED.policy`, c.environment, out.Target, raw); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.mfa_factors(environment,principal_id,factor_id,method,label,reference,secret_cipher,fingerprint,last_counter) SELECT environment,$3,factor_id,method,label,reference,secret_cipher,fingerprint,last_counter FROM keygate.account_setup_factors WHERE environment=$1 AND setup_id=$2 AND verified`, c.environment, out.ID, out.Target); e != nil {
		return e
	}
	if out.ResetPassword {
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.local_accounts(environment,username,principal_id,password_hash) VALUES($1,$2,$3,$4) ON CONFLICT(environment,username) DO UPDATE SET password_hash=EXCLUDED.password_hash,revision=local_accounts.revision+1,failures=0,locked_until='-infinity',enabled=true`, c.environment, out.Username, out.Target, newHash); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.local_login_budget(environment) VALUES($1) ON CONFLICT DO NOTHING`, c.environment); e != nil {
			return e
		}
	}
	if e = c.invalidateAccountSessions(ctx, tx, out.Target); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.account_setups SET consumed=true WHERE environment=$1 AND setup_id=$2`, c.environment, out.ID); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, out.Target, "account_setup_complete", out.Target, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
func factorIDs(factors []mfa.Factor) []string {
	out := []string{}
	for _, f := range factors {
		out = append(out, f.ID)
	}
	return out
}

// CompleteSetupHardware 只有可信注册插件的结果可落库；客户端不能自报verified或替换凭据标识。
func (c *DevelopmentControl) CompleteSetupHardware(ctx context.Context, tokenHash, id, reference, fingerprint, trace string) error {
	if reference == "" || len(reference) > 2048 || !validDigest(fingerprint) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, tokenHash)
	if e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.account_setup_factors SET reference=$4,fingerprint=$5,verified=true WHERE environment=$1 AND setup_id=$2 AND factor_id=$3 AND method='hardware' AND NOT verified AND delivered AND tries>0`, c.environment, out.ID, id, reference, fingerprint)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if e = c.audit(ctx, tx, trace, out.Target, "account_setup_hardware", out.Target, "verified"); e != nil {
		return e
	}
	return tx.Commit()
}

func (c *DevelopmentControl) ReserveSetupDelivery(ctx context.Context, tokenHash, id string) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, tokenHash)
	if e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.account_setup_factors SET sends=sends+1 WHERE environment=$1 AND setup_id=$2 AND factor_id=$3 AND NOT verified AND sends<3`, c.environment, out.ID, id)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrDenied
	}
	return tx.Commit()
}

// SaveSetupSecrets 只有候选占位胜者可封装并保存一次；失败不释放占位，避免重试透支持久密钥预算。
func (c *DevelopmentControl) SaveSetupSecrets(ctx context.Context, h, id string, cipher, verifier []byte) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	out, _, e := c.setupRead(ctx, tx, h)
	if e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.account_setup_factors SET secret_cipher=$4,verifier_cipher=$5,prepared=true WHERE environment=$1 AND setup_id=$2 AND factor_id=$3 AND NOT prepared AND NOT delivered`, c.environment, out.ID, id, cipher, verifier)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}
func (c *DevelopmentControl) PasswordLoginAvailable(ctx context.Context) bool {
	var available bool
	e := c.store.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.local_accounts a JOIN keygate.security_domains d USING(environment) WHERE a.environment=$1 AND a.enabled AND d.native_mfa_required)`, c.environment).Scan(&available)
	return e == nil && available
}
