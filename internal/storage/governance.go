package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"ex-keygate/internal/access"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const CreatePrincipal = "principal_create"
const UpdatePrincipal = "principal_update"
const UpdateApprovalPolicy = "approval_policy_update"

type GovernanceChange struct {
	Target       string         `json:"target,omitempty"`
	Issuer       string         `json:"issuer,omitempty"`
	Subject      string         `json:"subject,omitempty"`
	PersonID     string         `json:"personId,omitempty"`
	Enabled      bool           `json:"enabled"`
	Grants       []ConsoleGrant `json:"grants,omitempty"`
	M            int            `json:"m,omitempty"`
	Approvers    []string       `json:"approvers,omitempty"`
	Reason       string         `json:"reason"`
	EvidenceHash string         `json:"evidenceHash"`
}

func isGovernance(kind string) bool {
	return kind == CreatePrincipal || kind == UpdatePrincipal || kind == UpdateApprovalPolicy
}
func operationScope(op ControlOperation) string {
	if isGovernance(op.Kind) {
		return ""
	}
	return op.ClientID
}
func validGovernanceReason(s string) bool {
	return utf8.ValidString(s) && len(strings.TrimSpace(s)) >= 3 && len(s) <= 500 && !strings.ContainsFunc(s, unicode.IsControl)
}

// validateGovernanceOperation 在申请和执行时使用同一校验，身份关联只允许新增，不允许在线换绑自然人或issuer/sub。
func (c *DevelopmentControl) validateGovernanceOperation(ctx context.Context, tx *sql.Tx, op ControlOperation) error {
	g := op.Governance
	if g == nil || op.ClientID != "governance-management" || !validGovernanceReason(g.Reason) || !validDigest(g.EvidenceHash) {
		return ErrInvalid
	}
	copy := op
	copy.Governance = nil
	copy.Kind = ""
	copy.ClientID = ""
	copy.ExpectedRevision = 0
	raw, _ := json.Marshal(copy)
	zero, _ := json.Marshal(ControlOperation{})
	if !bytes.Equal(raw, zero) {
		return ErrInvalid
	}
	if op.Kind == UpdateApprovalPolicy {
		if g.Target != "" || g.Issuer != "" || g.Subject != "" || g.PersonID != "" || g.Enabled || len(g.Grants) != 0 || g.M < 2 || g.M > 32 || len(g.Approvers) < g.M || len(g.Approvers) > 32 {
			return ErrInvalid
		}
		var version uint64
		if e := tx.QueryRowContext(ctx, `SELECT version FROM keygate.control_policies WHERE environment=$1`, c.environment).Scan(&version); e != nil {
			return e
		}
		if version != op.ExpectedRevision {
			return ErrConflict
		}
		return c.governanceViable(ctx, tx, g.Approvers, g.M, "", false, nil)
	}
	if g.M != 0 || len(g.Approvers) != 0 {
		return ErrInvalid
	}
	if op.Kind == CreatePrincipal {
		p, e := access.NewPrincipal(g.Issuer, g.Subject, g.PersonID)
		if e != nil || g.Target != "" || op.ExpectedRevision != 0 || !g.Enabled || len(g.Grants) != 0 {
			return ErrInvalid
		}
		var count int
		var knownIssuer, exists bool
		e = tx.QueryRowContext(ctx, `SELECT count(*),bool_or(issuer=$2),bool_or(principal_id=$3 OR person_id=$4) FROM keygate.principals WHERE environment=$1`, c.environment, p.Issuer, p.ID, p.PersonID).Scan(&count, &knownIssuer, &exists)
		if e != nil {
			return e
		}
		if !knownIssuer || count >= 128 || exists {
			return ErrConflict
		}
		return nil
	}
	if !access.ValidID(g.Target) || g.Issuer != "" || g.Subject != "" || g.PersonID != "" || len(g.Grants) > 64 {
		return ErrInvalid
	}
	var revision uint64
	var enabled bool
	if e := tx.QueryRowContext(ctx, `SELECT revision,enabled FROM keygate.principals WHERE environment=$1 AND principal_id=$2`, c.environment, g.Target).Scan(&revision, &enabled); e != nil {
		return e
	}
	if revision != op.ExpectedRevision {
		return ErrConflict
	}
	seen := map[string]bool{}
	for _, grant := range g.Grants {
		if (access.Grant{PrincipalID: g.Target, Role: grant.Role, ClientID: grant.ClientID}).Validate() != nil {
			return ErrInvalid
		}
		key := string(grant.Role) + ":" + grant.ClientID
		if seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		if (grant.Role == access.PolicyAdmin || grant.Role == access.EmergencyOperator) && grant.ClientID != "" {
			return ErrInvalid
		}
		if grant.ClientID != "" {
			var exists bool
			if e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.clients WHERE environment=$1 AND client_id=$2 UNION ALL SELECT 1 FROM keygate.application_trust_services WHERE environment=$1 AND service_id=$2)`, c.environment, grant.ClientID).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				return ErrInvalid
			}
		}
	}
	old, e := consoleGrants(ctx, tx, c.environment, g.Target)
	if e != nil {
		return e
	}
	if enabled == g.Enabled && sameGrants(old, g.Grants) {
		return ErrConflict
	}
	var m int
	if e = tx.QueryRowContext(ctx, `SELECT threshold FROM keygate.control_policies WHERE environment=$1`, c.environment).Scan(&m); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, `SELECT principal_id FROM keygate.control_policy_members WHERE environment=$1 ORDER BY ordinal`, c.environment)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	return c.governanceViable(ctx, tx, ids, m, g.Target, g.Enabled, g.Grants)
}
func sameGrants(a, b []ConsoleGrant) bool {
	if len(a) != len(b) {
		return false
	}
	for _, g := range a {
		if !slices.Contains(b, g) {
			return false
		}
	}
	return true
}

// governanceViable 模拟变更后的人员与授权，拒绝破坏现有审批名单或移除最后可独立发起申请的管理员。
// 本规则不能证明真实员工身份；自然人归属仍由组织证据和当前多人审批核验。
func (c *DevelopmentControl) governanceViable(ctx context.Context, tx *sql.Tx, approvers []string, m int, target string, enabled bool, grants []ConsoleGrant) error {
	rows, e := tx.QueryContext(ctx, `SELECT p.principal_id,p.person_id,p.enabled,NOT d.native_mfa_required OR EXISTS(SELECT 1 FROM keygate.mfa_policies f WHERE f.environment=p.environment AND f.principal_id=p.principal_id) FROM keygate.principals p JOIN keygate.security_domains d ON d.environment=p.environment WHERE p.environment=$1`, c.environment)
	if e != nil {
		return e
	}
	type person struct {
		id, name     string
		enabled, mfa bool
		grants       []ConsoleGrant
	}
	people := map[string]*person{}
	for rows.Next() {
		p := new(person)
		if e = rows.Scan(&p.id, &p.name, &p.enabled, &p.mfa); e != nil {
			rows.Close()
			return e
		}
		people[p.id] = p
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for id, p := range people {
		p.grants, e = consoleGrants(ctx, tx, c.environment, id)
		if e != nil {
			return e
		}
		if id == target {
			p.enabled = enabled
			p.grants = grants
		}
	}
	has := func(p *person, r access.Role) bool {
		return p != nil && p.enabled && p.mfa && slices.Contains(p.grants, ConsoleGrant{Role: r, ClientID: ""})
	}
	seen := map[string]bool{}
	for _, id := range approvers {
		p := people[id]
		if !has(p, access.Approver) || seen[p.name] {
			return ErrDenied
		}
		seen[p.name] = true
	}
	if m < 2 || len(approvers) < m {
		return ErrDenied
	}
	viable := false
	for _, p := range people {
		if !seen[p.name] && has(p, access.PolicyAdmin) && has(p, access.Requester) && has(p, access.Viewer) {
			viable = true
		}
	}
	if !viable {
		return ErrDenied
	}
	return nil
}
func (c *DevelopmentControl) governanceApplicant(ctx context.Context, tx *sql.Tx, op ControlOperation, actor string) error {
	if !isGovernance(op.Kind) || op.Governance == nil {
		return nil
	}
	g := op.Governance
	var person string
	if e := tx.QueryRowContext(ctx, `SELECT person_id FROM keygate.principals WHERE environment=$1 AND principal_id=$2`, c.environment, actor).Scan(&person); e != nil {
		return e
	}
	if op.Kind == UpdatePrincipal {
		var targetPerson string
		if e := tx.QueryRowContext(ctx, `SELECT person_id FROM keygate.principals WHERE environment=$1 AND principal_id=$2`, c.environment, g.Target).Scan(&targetPerson); e != nil {
			return e
		}
		if person == targetPerson {
			return ErrDenied
		}
	}
	if op.Kind == CreatePrincipal && person == g.PersonID {
		return ErrDenied
	}
	return nil
}
func (c *DevelopmentControl) applyGovernance(ctx context.Context, tx *sql.Tx, op ControlOperation, approval, actor, trace string) error {
	g := op.Governance
	target := g.Target
	switch op.Kind {
	case CreatePrincipal:
		p, _ := access.NewPrincipal(g.Issuer, g.Subject, g.PersonID)
		target = p.ID
		if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.principals(environment,principal_id,issuer,subject_hash,person_id) VALUES($1,$2,$3,$4,$5)`, c.environment, p.ID, p.Issuer, p.SubjectHash, p.PersonID); e != nil {
			return e
		}
	case UpdatePrincipal:
		// 修订同时使旧MFA、旧票和H5会话失效；明确记录已有管理会话，阻止停用后恢复旧Cookie。
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.principals SET enabled=$3,revision=revision+1 WHERE environment=$1 AND principal_id=$2`, c.environment, target, g.Enabled); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.principal_session_blocks(environment,token_hash) SELECT $1,token_hash FROM keygate.sessions WHERE principal_id=$2 AND profile_hash=$3 ON CONFLICT DO NOTHING`, c.environment, target, c.profile); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.role_grants SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2`, c.environment, target); e != nil {
			return e
		}
		for _, grant := range g.Grants {
			if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,$3,$4) ON CONFLICT(environment,principal_id,role,client_id) DO UPDATE SET enabled=true,revision=role_grants.revision+1`, c.environment, target, grant.Role, grant.ClientID); e != nil {
				return e
			}
		}
	case UpdateApprovalPolicy:
		target = "approval-policy"
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.control_policies SET threshold=$2,sequential=true,version=version+1 WHERE environment=$1`, c.environment, g.M); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `DELETE FROM keygate.control_policy_members WHERE environment=$1`, c.environment); e != nil {
			return e
		}
		for i, id := range g.Approvers {
			if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.control_policy_members(environment,principal_id,ordinal) VALUES($1,$2,$3)`, c.environment, id, i); e != nil {
				return e
			}
		}
	}
	if e := c.audit(ctx, tx, trace, actor, op.Kind, target, "success"); e != nil {
		return e
	}
	return nil
}

// requestViewer 对人员治理快照使用组织管理读取边界；普通全域Viewer不能读取他人身份关联和授权明细。
func (c *DevelopmentControl) requestViewer(ctx context.Context, tx *sql.Tx, actor string, op ControlOperation) bool {
	if isGovernance(op.Kind) {
		return c.has(ctx, tx, actor, access.Viewer, "") && (c.has(ctx, tx, actor, access.PolicyAdmin, "") || c.has(ctx, tx, actor, access.Auditor, ""))
	}
	return c.has(ctx, tx, actor, access.Viewer, op.ClientID)
}
