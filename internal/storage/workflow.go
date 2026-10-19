package storage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"ex-keygate/internal/access"
	"ex-keygate/internal/manifest"
)

const (
	CreateClient    = "client_create"
	IssueKey        = "key_issue"
	ActivateKey     = "key_activate"
	DisableKey      = "key_disable"
	RecoverIssue    = "recovery_issue"
	RecoverActivate = "recovery_activate"
	ProvisionRoot   = "root_provision"
)

type ControlOperation struct {
	ProviderID                  string `json:"providerId,omitempty"`
	ProviderDigest              string `json:"providerDigest,omitempty"`
	RotationReason              string `json:"rotationReason,omitempty"`
	RecoveryID                  string `json:"recoveryId,omitempty"`
	IncidentID                  string `json:"incidentId,omitempty"`
	EvidenceHash                string `json:"evidenceHash,omitempty"`
	RotationOf                  uint64 `json:"rotationOf,string,omitempty"`
	RecipientSigningKey         string `json:"recipientSigningKey,omitempty"`
	RecipientSigningFingerprint string `json:"recipientSigningFingerprint,omitempty"`
	Kind                        string `json:"kind"`
	ClientID                    string `json:"clientId"`
	ExpectedRevision            uint64 `json:"expectedRevision,string"`
	Name                        string `json:"name"`
	ProfileID                   string `json:"profileId"`
	ProfileVersion              uint64 `json:"profileVersion,string"`
	KeyVersion                  uint64 `json:"keyVersion,string,omitempty"`
	RootID                      string `json:"rootId,omitempty"`
	RecipientPublicKey          string `json:"recipientPublicKey,omitempty"`
	RecipientFingerprint        string `json:"recipientFingerprint,omitempty"`
	NotAfter                    string `json:"notAfter,omitempty"`
	RetireAt                    string `json:"retireAt,omitempty"`
}

type controlMember struct {
	PrincipalID   string `json:"principalId"`
	PersonID      string `json:"personId"`
	Revision      int64  `json:"revision,string"`
	GrantRevision int64  `json:"grantRevision,string"`
	GrantScope    string `json:"grantScope"`
}
type controlManifest struct {
	ProviderPolicy *ProviderPolicySnapshot `json:"providerPolicy,omitempty"`
	ProviderAdmin  *controlMember          `json:"providerAdmin,omitempty"`
	Schema         string                  `json:"schema"`
	Environment    string                  `json:"environment"`
	RequestID      string                  `json:"requestId"`
	Applicant      controlMember           `json:"applicant"`
	Operation      ControlOperation        `json:"operation"`
	PolicyVersion  int64                   `json:"policyVersion,string"`
	Threshold      int                     `json:"threshold"`
	Approvers      []controlMember         `json:"approvers"`
	Created        string                  `json:"created"`
	Expires        string                  `json:"expires"`
}
type ControlRequest struct {
	ID       string          `json:"id"`
	Digest   string          `json:"digest"`
	Manifest json.RawMessage `json:"manifest"`
	Decision string          `json:"decision"`
	Executed bool            `json:"executed"`
}

func digestBytes(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func (c *DevelopmentControl) grantRevision(ctx context.Context, tx *sql.Tx, id string, role access.Role, client string) (int64, string, error) {
	var rev int64
	var scope string
	// 优先采用客户端精确授权；任何被快照引用的授权修订变化都会使旧审批失效。
	e := tx.QueryRowContext(ctx, `SELECT revision,client_id FROM keygate.role_grants WHERE environment=$1 AND principal_id=$2 AND role=$3 AND enabled AND (client_id='' OR client_id=$4) ORDER BY (client_id=$4) DESC LIMIT 1`, c.environment, id, role, client).Scan(&rev, &scope)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, "", ErrDenied
	}
	return rev, scope, e
}
func (c *DevelopmentControl) eligible(ctx context.Context, tx *sql.Tx, id string, role access.Role, client string) (controlMember, error) {
	var m controlMember
	e := tx.QueryRowContext(ctx, `SELECT principal_id,person_id,revision FROM keygate.principals WHERE environment=$1 AND principal_id=$2 AND enabled`, c.environment, id).Scan(&m.PrincipalID, &m.PersonID, &m.Revision)
	if errors.Is(e, sql.ErrNoRows) {
		return m, ErrDenied
	}
	if e != nil {
		return m, e
	}
	m.GrantRevision, m.GrantScope, e = c.grantRevision(ctx, tx, id, role, client)
	return m, e
}
func (c *DevelopmentControl) validateOperation(ctx context.Context, tx *sql.Tx, op ControlOperation) error {
	if !access.ValidID(op.ClientID) || op.ExpectedRevision > 9007199254740991 {
		return ErrInvalid
	}
	if op.Kind != EnableProvider && (op.ProviderID != "" || op.ProviderDigest != "") {
		return ErrInvalid
	}
	if op.RotationReason != "" && (op.Kind != IssueKey || op.RotationOf == 0) {
		return ErrInvalid
	}
	if op.Kind != RecoverIssue && op.Kind != RecoverActivate && (op.RecoveryID != "" || op.IncidentID != "" || op.EvidenceHash != "") {
		return ErrInvalid
	}
	switch op.Kind {
	case EnableProvider:
		return c.validateProviderOperation(ctx, tx, op)
	case ProvisionRoot:
		if e := c.requireInternalProvider(ctx, tx); e != nil {
			return e
		}
		if op.ClientID != "root-management" || !access.ValidID(op.RootID) || op.KeyVersion != 0 || op.RotationOf != 0 || op.ExpectedRevision != 0 || op.Name != "" || op.ProfileID != "" || op.ProfileVersion != 0 || op.RecipientPublicKey != "" || op.RecipientFingerprint != "" || op.RecipientSigningKey != "" || op.RecipientSigningFingerprint != "" || op.NotAfter != "" || op.RetireAt != "" {
			return ErrInvalid
		}
		var n int
		if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM keygate.client_roots WHERE environment=$1`, c.environment).Scan(&n); e != nil {
			return e
		}
		if n >= 16 {
			return ErrConflict
		}
		var exists bool
		if e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.root_budgets WHERE root_id=$1)`, op.RootID).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return ErrConflict
		}
		return nil
	case CreateClient:
		if op.ClientID == "root-management" || op.ClientID == "provider-management" {
			return ErrInvalid
		}
		if op.RotationOf != 0 || op.RecipientSigningKey != "" || op.RecipientSigningFingerprint != "" || op.RootID != "" || op.KeyVersion != 0 || op.RecipientPublicKey != "" || op.RecipientFingerprint != "" || op.NotAfter != "" || op.RetireAt != "" || op.ExpectedRevision != 0 || !access.ValidID(op.ProfileID) || op.ProfileVersion == 0 || op.ProfileVersion > 9007199254740991 || len(op.Name) == 0 || len(op.Name) > 128 || !utf8.ValidString(op.Name) || strings.TrimSpace(op.Name) != op.Name {
			return ErrInvalid
		}
		var valid bool
		e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.auth_profiles WHERE environment=$1 AND profile_id=$2 AND version=$3 AND enabled) AND NOT EXISTS(SELECT 1 FROM keygate.clients WHERE environment=$1 AND client_id=$4)`, c.environment, op.ProfileID, op.ProfileVersion, op.ClientID).Scan(&valid)
		if e != nil {
			return e
		}
		if !valid {
			return ErrConflict
		}
		return nil
	case IssueKey, ActivateKey, DisableKey, RecoverIssue, RecoverActivate:
		return c.validateKeyOperation(ctx, tx, op)
	default:
		return ErrInvalid
	}
}

// Submit 冻结服务端生成的完整清单，幂等键只重用完全相同参数的申请，不能改变已投票内容。
func (c *DevelopmentControl) Submit(ctx context.Context, token string, op ControlOperation, idempotency, trace string) (ControlRequest, error) {
	if !access.ValidID(idempotency) || !access.ValidID(trace) {
		return ControlRequest{}, ErrInvalid
	}
	params, e := manifest.Canonical(op)
	if e != nil {
		return ControlRequest{}, ErrInvalid
	}
	parameterDigest := digestBytes(params)
	tx, e := c.begin(ctx)
	if e != nil {
		return ControlRequest{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return ControlRequest{}, e
	}
	applicant, e := c.eligible(ctx, tx, a.id, access.Requester, op.ClientID)
	if e != nil {
		return ControlRequest{}, e
	}
	if (op.Kind == ProvisionRoot || op.Kind == EnableProvider) && applicant.GrantScope != "" {
		return ControlRequest{}, ErrDenied
	}
	var admin *controlMember
	if op.Kind == EnableProvider {
		m, e := c.eligible(ctx, tx, a.id, access.PolicyAdmin, "")
		if e != nil {
			return ControlRequest{}, e
		}
		if m.GrantScope != "" {
			return ControlRequest{}, ErrDenied
		}
		admin = &m
	}
	var previous, previousDigest string
	e = tx.QueryRowContext(ctx, `SELECT request_id,parameters_digest FROM keygate.control_idempotency WHERE environment=$1 AND principal_id=$2 AND idempotency_key=$3`, c.environment, a.id, idempotency).Scan(&previous, &previousDigest)
	if e == nil {
		if previousDigest != parameterDigest {
			return ControlRequest{}, ErrConflict
		}
		r, _, e := c.loadRequest(ctx, tx, previous)
		if e != nil {
			return ControlRequest{}, e
		}
		if e = tx.Commit(); e != nil {
			return ControlRequest{}, e
		}
		return r, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return ControlRequest{}, e
	}
	if e = c.validateOperation(ctx, tx, op); e != nil {
		return ControlRequest{}, e
	}
	var policyVersion int64
	var threshold int
	if e = tx.QueryRowContext(ctx, `SELECT version,threshold FROM keygate.control_policies WHERE environment=$1`, c.environment).Scan(&policyVersion, &threshold); e != nil {
		return ControlRequest{}, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT principal_id FROM keygate.control_policy_members WHERE environment=$1 ORDER BY principal_id`, c.environment)
	if e != nil {
		return ControlRequest{}, e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return ControlRequest{}, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ControlRequest{}, e
	}
	var members []controlMember
	seen := map[string]bool{a.person: true}
	for _, id := range ids {
		m, e := c.eligible(ctx, tx, id, access.Approver, op.ClientID)
		if errors.Is(e, ErrDenied) {
			continue
		}
		if e != nil {
			return ControlRequest{}, e
		}
		if (op.Kind == ProvisionRoot || op.Kind == EnableProvider) && m.GrantScope != "" {
			continue
		}
		if !seen[m.PersonID] {
			members = append(members, m)
			seen[m.PersonID] = true
		}
	}
	if len(members) < threshold || threshold < 2 {
		return ControlRequest{}, ErrDenied
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return ControlRequest{}, e
	}
	now = now.UTC().Truncate(time.Millisecond)
	expires := now.Add(5 * time.Minute)
	id, e := controlID()
	if e != nil {
		return ControlRequest{}, e
	}
	m := controlManifest{Schema: "keygate-control-jcs-v1", Environment: c.environment, RequestID: id, Applicant: applicant, Operation: op, PolicyVersion: policyVersion, Threshold: threshold, Approvers: members, Created: now.Format("2006-01-02T15:04:05.000Z"), Expires: expires.Format("2006-01-02T15:04:05.000Z"), ProviderAdmin: admin}
	if needsProviderSnapshot(op.Kind) {
		snapshot, e := c.providerSnapshot(ctx, tx, "internal-software")
		if e != nil {
			return ControlRequest{}, e
		}
		m.ProviderPolicy = &snapshot
	}
	raw, e := manifest.Canonical(m)
	if e != nil || len(raw) > 65536 {
		return ControlRequest{}, ErrInvalid
	}
	digest := digestBytes(raw)
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.control_requests(environment,request_id,applicant_id,manifest,digest,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, c.environment, id, a.id, raw, digest, expires); e != nil {
		return ControlRequest{}, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.control_idempotency(environment,principal_id,idempotency_key,parameters_digest,request_id) VALUES($1,$2,$3,$4,$5)`, c.environment, a.id, idempotency, parameterDigest, id); e != nil {
		return ControlRequest{}, e
	}
	if e = c.audit(ctx, tx, trace, a.id, "control_submit", id, "pending"); e != nil {
		return ControlRequest{}, e
	}
	if e = tx.Commit(); e != nil {
		return ControlRequest{}, e
	}
	c.logger.InfoContext(ctx, "变更申请已创建", "request_id", trace, "approval_id", id, "client_id", op.ClientID, "result", "pending")
	return ControlRequest{id, digest, raw, "pending", false}, nil
}
func (c *DevelopmentControl) loadRequest(ctx context.Context, tx *sql.Tx, id string) (ControlRequest, controlManifest, error) {
	var r ControlRequest
	var m controlManifest
	e := tx.QueryRowContext(ctx, `SELECT request_id,digest,manifest,decision,executed FROM keygate.control_requests WHERE environment=$1 AND request_id=$2 FOR UPDATE`, c.environment, id).Scan(&r.ID, &r.Digest, &r.Manifest, &r.Decision, &r.Executed)
	if e != nil {
		return r, m, e
	}
	if digestBytes(r.Manifest) != r.Digest {
		return r, m, ErrConflict
	}
	d := json.NewDecoder(strings.NewReader(string(r.Manifest)))
	d.DisallowUnknownFields()
	if e = d.Decode(&m); e != nil {
		return r, m, ErrInvalid
	}
	canonical, e := manifest.Canonical(m)
	if e != nil || string(canonical) != string(r.Manifest) || m.Schema != "keygate-control-jcs-v1" || m.Environment != c.environment || m.RequestID != id {
		return r, m, ErrConflict
	}
	return r, m, nil
}
func (c *DevelopmentControl) liveManifest(ctx context.Context, tx *sql.Tx, m controlManifest) error {
	now, e := controlNow(ctx, tx)
	if e != nil {
		return e
	}
	expires, e := time.Parse(time.RFC3339Nano, m.Expires)
	if e != nil || !now.Before(expires) {
		return ErrConflict
	}
	var version int64
	var threshold int
	if e = tx.QueryRowContext(ctx, `SELECT version,threshold FROM keygate.control_policies WHERE environment=$1`, c.environment).Scan(&version, &threshold); e != nil {
		return e
	}
	if version != m.PolicyVersion || threshold != m.Threshold {
		return ErrConflict
	}
	applicant, e := c.eligible(ctx, tx, m.Applicant.PrincipalID, access.Requester, m.Operation.ClientID)
	if e != nil {
		return e
	}
	if applicant != m.Applicant {
		return ErrConflict
	}
	if needsProviderSnapshot(m.Operation.Kind) {
		snapshot, e := c.providerSnapshot(ctx, tx, "internal-software")
		if e != nil {
			return e
		}
		if m.ProviderPolicy == nil || *m.ProviderPolicy != snapshot {
			return ErrConflict
		}
	}
	if m.Operation.Kind == EnableProvider {
		admin, e := c.eligible(ctx, tx, m.Applicant.PrincipalID, access.PolicyAdmin, "")
		if e != nil {
			return e
		}
		if m.ProviderAdmin == nil || *m.ProviderAdmin != admin || admin.GrantScope != "" {
			return ErrConflict
		}
	}
	return nil
}
func (c *DevelopmentControl) currentMember(ctx context.Context, tx *sql.Tx, m controlManifest, id string) (controlMember, error) {
	var snapshot controlMember
	for _, member := range m.Approvers {
		if member.PrincipalID == id {
			snapshot = member
			break
		}
	}
	if snapshot.PrincipalID == "" || snapshot.PersonID == m.Applicant.PersonID {
		return snapshot, ErrDenied
	}
	current, e := c.eligible(ctx, tx, id, access.Approver, m.Operation.ClientID)
	if e != nil {
		return current, e
	}
	if current != snapshot {
		return current, ErrConflict
	}
	var member bool
	e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.control_policy_members WHERE environment=$1 AND principal_id=$2)`, c.environment, id).Scan(&member)
	if e != nil {
		return current, e
	}
	if !member {
		return current, ErrDenied
	}
	return current, nil
}
func (c *DevelopmentControl) Request(ctx context.Context, token, id string) (ControlRequest, error) {
	if !access.ValidID(id) {
		return ControlRequest{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return ControlRequest{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return ControlRequest{}, e
	}
	r, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return ControlRequest{}, e
	}
	if !(a.id == m.Applicant.PrincipalID && c.has(ctx, tx, a.id, access.Requester, m.Operation.ClientID)) && !c.has(ctx, tx, a.id, access.Viewer, m.Operation.ClientID) {
		if _, e = c.currentMember(ctx, tx, m, a.id); e != nil {
			return ControlRequest{}, ErrDenied
		}
	}
	if e = tx.Commit(); e != nil {
		return ControlRequest{}, e
	}
	return r, nil
}

// Vote 每个自然人只能计票一次，拒绝票立即终止申请；执行仍会复查票的当前资格。
func (c *DevelopmentControl) Vote(ctx context.Context, token, id, digest string, accept bool, trace string) (ControlRequest, error) {
	if !access.ValidID(id) || !access.ValidID(trace) {
		return ControlRequest{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return ControlRequest{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return ControlRequest{}, e
	}
	r, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return ControlRequest{}, e
	}
	if subtle.ConstantTimeCompare([]byte(r.Digest), []byte(digest)) != 1 {
		return ControlRequest{}, ErrConflict
	}
	if r.Decision != "pending" || r.Executed {
		return ControlRequest{}, ErrConflict
	}
	if e = c.liveManifest(ctx, tx, m); e != nil {
		return ControlRequest{}, e
	}
	member, e := c.currentMember(ctx, tx, m, a.id)
	if e != nil {
		return ControlRequest{}, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.control_votes(environment,request_id,principal_id,person_id,principal_revision,grant_revision,grant_scope,accepted) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.environment, id, a.id, a.person, member.Revision, member.GrantRevision, member.GrantScope, accept); e != nil {
		return ControlRequest{}, e
	}
	var votes int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM keygate.control_votes WHERE environment=$1 AND request_id=$2 AND accepted`, c.environment, id).Scan(&votes); e != nil {
		return ControlRequest{}, e
	}
	if !accept {
		r.Decision = "rejected"
	} else if votes >= m.Threshold {
		r.Decision = "approved"
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET decision=$3 WHERE environment=$1 AND request_id=$2`, c.environment, id, r.Decision); e != nil {
		return ControlRequest{}, e
	}
	result := "accepted"
	if !accept {
		result = "rejected"
	}
	if e = c.audit(ctx, tx, trace, a.id, "control_vote", id, result); e != nil {
		return ControlRequest{}, e
	}
	if e = tx.Commit(); e != nil {
		return ControlRequest{}, e
	}
	c.logger.InfoContext(ctx, "审批投票已记录", "request_id", trace, "approval_id", id, "result", result, "decision", r.Decision)
	return r, nil
}
func (c *DevelopmentControl) verifyVotes(ctx context.Context, tx *sql.Tx, m controlManifest) error {
	rows, e := tx.QueryContext(ctx, `SELECT principal_id,person_id,principal_revision,grant_revision,grant_scope,accepted FROM keygate.control_votes WHERE environment=$1 AND request_id=$2 ORDER BY principal_id`, c.environment, m.RequestID)
	if e != nil {
		return e
	}
	var members []controlMember
	for rows.Next() {
		var member controlMember
		var accepted bool
		if e = rows.Scan(&member.PrincipalID, &member.PersonID, &member.Revision, &member.GrantRevision, &member.GrantScope, &accepted); e != nil {
			rows.Close()
			return e
		}
		if !accepted {
			rows.Close()
			return ErrDenied
		}
		members = append(members, member)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(members) < m.Threshold {
		return ErrDenied
	}
	people := map[string]bool{m.Applicant.PersonID: true}
	for _, v := range members {
		current, e := c.currentMember(ctx, tx, m, v.PrincipalID)
		if e != nil {
			return e
		}
		if current != v || people[v.PersonID] {
			return ErrDenied
		}
		people[v.PersonID] = true
	}
	return nil
}

// ExecuteLocal 是可信进程内执行器，不向外部授予 executor 角色；仅消费原清单，无额外执行参数。
// 客户端创建和密钥状态变更与执行记录、资格检查及审计同事务提交。
// 签发只接收专用软件执行器的内部预计算结果，普通调用不能自行注入密文或明文。
func (c *DevelopmentControl) ExecuteLocal(ctx context.Context, id, digest, trace string) error {
	return c.executePrepared(ctx, id, digest, trace, nil)
}

func (c *DevelopmentControl) executePrepared(ctx context.Context, id, digest, trace string, prepared *preparedKey) error {
	return c.executePreparedAs(ctx, id, digest, trace, prepared, "")
}

// ExecuteRequested 仅允许原申请人触发获批清单，仍由内部执行器完成受控操作。
func (c *DevelopmentControl) ExecuteRequested(ctx context.Context, token, id, digest, trace string) error {
	if token == "" {
		return ErrDenied
	}
	return c.executePreparedAs(ctx, id, digest, trace, nil, token)
}
func (c *DevelopmentControl) executePreparedAs(ctx context.Context, id, digest, trace string, prepared *preparedKey, token string) error {
	if !access.ValidID(id) || !access.ValidID(trace) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return e
	}
	if token != "" {
		if e = c.executionActor(ctx, tx, token, m); e != nil {
			return e
		}
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(r.Digest)) != 1 {
		return ErrConflict
	}
	if r.Executed {
		if prepared != nil && prepared.newRoot != nil {
			if e = prepared.newRoot.rootMatches(ctx, tx); e != nil {
				return e
			}
		}
		return tx.Commit()
	}
	if r.Decision != "approved" {
		return ErrDenied
	}
	if e = c.liveManifest(ctx, tx, m); e != nil {
		return e
	}
	if e = c.verifyVotes(ctx, tx, m); e != nil {
		return e
	}
	if e = c.validateOperation(ctx, tx, m.Operation); e != nil {
		return e
	}
	op := m.Operation
	if op.Kind == CreateClient {
		result, e := tx.ExecContext(ctx, `INSERT INTO keygate.clients(environment,client_id,name,client_type,profile_id,profile_version,state) SELECT $1,$2,$3,client_type,profile_id,version,'enabled' FROM keygate.auth_profiles WHERE environment=$1 AND profile_id=$4 AND version=$5 AND enabled`, c.environment, op.ClientID, op.Name, op.ProfileID, op.ProfileVersion)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrConflict
		}
	} else if op.Kind == EnableProvider {
		if e = c.applyProviderOperation(ctx, tx, op); e != nil {
			return e
		}
	} else if e = c.applyKeyOperation(ctx, tx, m, prepared); e != nil {
		return e
	}
	execution, e := controlID()
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.control_executions(environment,request_id,execution_id,digest,state) VALUES($1,$2,$3,$4,'succeeded')`, c.environment, id, execution, digest); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET executed=true WHERE environment=$1 AND request_id=$2`, c.environment, id); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, "executor-service", "control_execute", id, "success"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.InfoContext(ctx, "获批本地操作执行完成", "request_id", trace, "approval_id", id, "client_id", op.ClientID, "operation", op.Kind, "result", "success")
	return nil
}
