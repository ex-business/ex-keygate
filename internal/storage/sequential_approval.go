package storage

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"ex-keygate/internal/access"
	"strings"
	"unicode/utf8"
)

type ApprovalProgress struct {
	M                  int    `json:"m"`
	N                  int    `json:"n"`
	Processed          int    `json:"processed"`
	Completed          int    `json:"completed"`
	CurrentPrincipalID string `json:"currentPrincipalId,omitempty"`
}

// ConfigureSequentialApprovalOffline 冻结外部核验后的自然人顺序；调整名单或阈值推进策略版本，使旧申请不能沿用旧票。
func (c *DevelopmentControl) ConfigureSequentialApprovalOffline(ctx context.Context, approvers []string, threshold int, witnesses [2]string, evidence, trace string) error {
	if len(approvers) < 2 || len(approvers) > 32 || threshold < 2 || threshold > len(approvers) || !validDigest(evidence) || !identifier.MatchString(trace) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var people int
	var enforced bool
	if e = tx.QueryRowContext(ctx, `SELECT native_mfa_required FROM keygate.security_domains WHERE environment=$1`, c.environment).Scan(&enforced); e != nil {
		return e
	}
	if !enforced {
		return ErrDenied
	}
	if e = tx.QueryRowContext(ctx, `SELECT count(DISTINCT person_id) FROM keygate.principals WHERE environment=$1 AND enabled AND principal_id IN($2,$3)`, c.environment, witnesses[0], witnesses[1]).Scan(&people); e != nil {
		return e
	}
	if people != 2 {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, id := range approvers {
		member, e := c.eligible(ctx, tx, id, access.Approver, "")
		if e != nil {
			return e
		}
		if member.GrantScope != "" || seen[member.PersonID] {
			return ErrDenied
		}
		seen[member.PersonID] = true
		if _, _, _, e = c.mfaPolicy(ctx, tx, id); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_policies SET sequential=true,threshold=$2,version=version+1 WHERE environment=$1`, c.environment, threshold); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM keygate.control_policy_members WHERE environment=$1`, c.environment); e != nil {
		return e
	}
	for ordinal, id := range approvers {
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.control_policy_members(environment,principal_id,ordinal) VALUES($1,$2,$3)`, c.environment, id, ordinal); e != nil {
			return e
		}
	}
	if e = c.audit(ctx, tx, trace, "offline-bootstrap", "approval_sequence_configure", evidence, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *DevelopmentControl) approvalProgress(ctx context.Context, tx *sql.Tx, r *ControlRequest, m controlManifest) error {
	if !m.Sequential {
		return nil
	}
	p := &ApprovalProgress{M: m.Threshold, N: len(m.Approvers)}
	if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM keygate.control_votes WHERE environment=$1 AND request_id=$2 AND accepted`, c.environment, m.RequestID).Scan(&p.Completed); e != nil {
		return e
	}
	var skipped int
	if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM keygate.control_skips WHERE environment=$1 AND request_id=$2`, c.environment, m.RequestID).Scan(&skipped); e != nil {
		return e
	}
	p.Processed = p.Completed + skipped
	if r.Decision == "pending" && p.Completed < m.Threshold && p.Processed < len(m.Approvers) {
		p.CurrentPrincipalID = m.Approvers[p.Processed].PrincipalID
	}
	r.Progress = p
	return nil
}

// SkipSequential 当前人员验证后可以明确放弃并转交，但不能代他人跳步，也不把放弃计为赞成。
// 剩余人员不足M时直接拒绝；不会自动降低门槛或补造一张票。
func (c *DevelopmentControl) SkipSequential(ctx context.Context, token, id, digest, reason, trace string) (ControlRequest, error) {
	if !identifier.MatchString(id) || !identifier.MatchString(trace) || len(reason) == 0 || len(reason) > 256 || !utf8.ValidString(reason) || strings.TrimSpace(reason) != reason {
		return ControlRequest{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return ControlRequest{}, e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, true)
	if e != nil {
		return ControlRequest{}, e
	}
	r, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return r, e
	}
	if !m.Sequential || r.Decision != "pending" || r.Executed || subtle.ConstantTimeCompare([]byte(r.Digest), []byte(digest)) != 1 {
		return r, ErrConflict
	}
	if e = c.liveManifest(ctx, tx, m); e != nil {
		return r, e
	}
	member, e := c.currentMember(ctx, tx, m, a.id)
	if e != nil {
		return r, e
	}
	if e = c.requireCurrentTurn(ctx, tx, m, a.id); e != nil {
		return r, e
	}
	if e = c.requireMFAForPurpose(ctx, tx, token, a, id); e != nil {
		return r, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.control_skips(environment,request_id,principal_id,person_id,principal_revision,grant_revision,grant_scope,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.environment, id, a.id, a.person, member.Revision, member.GrantRevision, member.GrantScope, reason); e != nil {
		return r, e
	}
	if e = c.approvalProgress(ctx, tx, &r, m); e != nil {
		return r, e
	}
	if r.Progress.Completed+len(m.Approvers)-r.Progress.Processed < m.Threshold {
		r.Decision = "rejected"
		r.Progress.CurrentPrincipalID = ""
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET decision=$3 WHERE environment=$1 AND request_id=$2`, c.environment, id, r.Decision); e != nil {
		return r, e
	}
	if e = c.audit(ctx, tx, trace, a.id, "control_skip", id, "abstained"); e != nil {
		return r, e
	}
	if e = c.syncApprovalNotifications(ctx, tx, id); e != nil {
		return ControlRequest{}, e
	}
	if e = tx.Commit(); e != nil {
		return ControlRequest{}, e
	}
	return r, nil
}
