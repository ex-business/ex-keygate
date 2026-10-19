package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"time"

	"ex-keygate/internal/access"
	"ex-keygate/internal/client"
	"ex-keygate/internal/config"
)

var (
	ErrDenied   = errors.New("local authorization denied")
	ErrConflict = errors.New("security state conflict")
)

// DevelopmentControl 仅供开发/测试可信适配器调用；不接收外部自报的 actor 或 MFA。
// profile 固定在服务构造时，避免请求方借另一身份源的会话认领本地权限。
type DevelopmentControl struct {
	store                *Store
	environment, profile string
	logger               *slog.Logger
}

func NewDevelopmentControl(mode config.Environment, environment, profile string, s *Store) (*DevelopmentControl, error) {
	if (mode != config.Development && mode != config.Test) || !access.ValidID(environment) || len(profile) != 64 || s == nil || s.db == nil {
		return nil, ErrInvalid
	}
	if _, e := hex.DecodeString(profile); e != nil {
		return nil, ErrInvalid
	}
	return &DevelopmentControl{s, environment, profile, slog.Default()}, nil
}

type Bootstrap struct {
	Principals []access.Principal
	Grants     []access.Grant
	Profiles   []client.Profile
	Approvers  []string
	Threshold  int
	// 两名离线核验人及确认记录摘要；此接口不宣称验证了真实人工签名。
	Witnesses    [2]string
	EvidenceHash string
}

func controlID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func (c *DevelopmentControl) audit(ctx context.Context, tx *sql.Tx, request, actor, action, target, result string) error {
	event, err := controlID()
	if err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, Audit{event, request, actor, action, target, result}); err != nil {
		return err
	}
	scope, err := c.auditScope(ctx, tx, action, target)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO keygate.scoped_audit(event_id,environment,client_id) VALUES($1,$2,$3)`, event, c.environment, scope)
	return err
}

// BootstrapOffline 只能从受控离线入口调用。安全域行是永久初始化哨兵，撤空人员也不能重开。
// 真实人工核验必须由操作者在系统外完成；模拟身份仅用于开发，不能据此获得生产权限。
func (c *DevelopmentControl) BootstrapOffline(ctx context.Context, b Bootstrap, request string) error {
	if !identifier.MatchString(request) || len(b.Principals) < 3 || len(b.Principals) > 128 || len(b.Profiles) == 0 || len(b.Profiles) > 32 || len(b.Grants) > 1024 || b.Threshold < 2 || b.Threshold > 32 || len(b.Approvers) < b.Threshold || len(b.Approvers) > 32 || len(b.EvidenceHash) != 64 {
		return ErrInvalid
	}
	if _, e := hex.DecodeString(b.EvidenceHash); e != nil {
		return ErrInvalid
	}
	people := map[string]string{}
	for _, p := range b.Principals {
		if p.Validate() != nil || people[p.ID] != "" {
			return ErrInvalid
		}
		people[p.ID] = p.PersonID
	}
	if people[b.Witnesses[0]] == "" || people[b.Witnesses[1]] == "" || people[b.Witnesses[0]] == people[b.Witnesses[1]] {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, p := range b.Approvers {
		person := people[p]
		if person == "" || seen[person] {
			return ErrInvalid
		}
		seen[person] = true
		if !slices.ContainsFunc(b.Grants, func(g access.Grant) bool { return g.PrincipalID == p && g.Role == access.Approver && g.ClientID == "" }) {
			return ErrInvalid
		}
	}
	for _, g := range b.Grants {
		if g.Validate() != nil || people[g.PrincipalID] == "" {
			return ErrInvalid
		}
	}
	for _, p := range b.Profiles {
		if access.ValidateProfileV1(p) != nil {
			return ErrInvalid
		}
	}
	tx, err := c.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 插入唯一域行与全部初始授权同事务，任何约束或审计失败都不会留下半初始化状态。
	if _, err = tx.ExecContext(ctx, `INSERT INTO keygate.security_domains(environment,bootstrap_evidence_hash) VALUES($1,$2)`, c.environment, b.EvidenceHash); err != nil {
		return err
	}
	for _, p := range b.Principals {
		if _, err = tx.ExecContext(ctx, `INSERT INTO keygate.principals(environment,principal_id,issuer,subject_hash,person_id) VALUES($1,$2,$3,$4,$5)`, c.environment, p.ID, p.Issuer, p.SubjectHash, p.PersonID); err != nil {
			return err
		}
	}
	for _, g := range b.Grants {
		if _, err = tx.ExecContext(ctx, `INSERT INTO keygate.role_grants(environment,principal_id,role,client_id) VALUES($1,$2,$3,$4)`, c.environment, g.PrincipalID, g.Role, g.ClientID); err != nil {
			return err
		}
	}
	for _, p := range b.Profiles {
		if _, err = tx.ExecContext(ctx, `INSERT INTO keygate.auth_profiles(environment,profile_id,version,client_type,method,storage,provider_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, c.environment, p.ID, p.Version, p.ClientType, p.Method, p.Storage, p.ProviderID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO keygate.control_policies(environment,threshold) VALUES($1,$2)`, c.environment, b.Threshold); err != nil {
		return err
	}
	for _, p := range b.Approvers {
		if _, err = tx.ExecContext(ctx, `INSERT INTO keygate.control_policy_members(environment,principal_id) VALUES($1,$2)`, c.environment, p); err != nil {
			return err
		}
	}
	if err = c.audit(ctx, tx, request, "offline-bootstrap", "control_bootstrap", c.environment, "success"); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	c.logger.InfoContext(ctx, "开发授权域初始化完成", "request_id", request, "environment", c.environment, "result", "success")
	return nil
}

// begin 先锁安全域控制行，统一排序所有撤权、投票和执行；首期牺牲同域写吞吐换取清晰原子边界。
// 普通元信息读取也在该边界内检查权限，避免撤权后继续返回受保护数据。
func (c *DevelopmentControl) begin(ctx context.Context) (*sql.Tx, error) {
	tx, e := c.store.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	var rev int64
	e = tx.QueryRowContext(ctx, `SELECT revision FROM keygate.security_domains WHERE environment=$1 FOR UPDATE`, c.environment).Scan(&rev)
	if e != nil {
		tx.Rollback()
		if errors.Is(e, sql.ErrNoRows) {
			return nil, ErrDenied
		}
		return nil, e
	}
	return tx, nil
}

type controlActor struct {
	id, person string
	revision   int64
}

// actor 只从有效、指定登录 Profile 的短期会话解析身份，不信任调用者提供的账号字符串。
// 敏感操作使用数据库时间检查原始 auth_time，开发模拟 MFA 不会被升级为生产强认证。
func (c *DevelopmentControl) actor(ctx context.Context, tx *sql.Tx, token string, sensitive bool) (controlActor, error) {
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(token)
	if decodeErr != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return controlActor{}, ErrDenied
	}
	h := sha256.Sum256([]byte(token))
	var a controlActor
	var fresh bool
	err := tx.QueryRowContext(ctx, `SELECT p.principal_id,p.person_id,p.revision,
 s.authenticated_at<=clock_timestamp() AND s.authenticated_at>clock_timestamp()-interval '5 minutes'
 FROM keygate.sessions s JOIN keygate.principals p ON p.principal_id=s.principal_id AND p.environment=$1
 WHERE s.token_hash=$2 AND s.profile_hash=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND p.enabled FOR UPDATE OF s,p`, c.environment, h[:], c.profile).Scan(&a.id, &a.person, &a.revision, &fresh)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && sensitive && !fresh) {
		return a, ErrDenied
	}
	return a, err
}
func (c *DevelopmentControl) has(ctx context.Context, tx *sql.Tx, principal string, role access.Role, clientID string) bool {
	var yes bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.role_grants WHERE environment=$1 AND principal_id=$2 AND role=$3 AND enabled AND (client_id='' OR client_id=$4))`, c.environment, principal, role, clientID).Scan(&yes)
	return err == nil && yes
}
func (c *DevelopmentControl) Client(ctx context.Context, token string, id string) (access.Client, error) {
	if !identifier.MatchString(id) {
		return access.Client{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return access.Client{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return access.Client{}, e
	}
	if !c.has(ctx, tx, a.id, access.Viewer, id) {
		return access.Client{}, ErrDenied
	}
	var out access.Client
	e = tx.QueryRowContext(ctx, `SELECT environment,client_id,name,client_type,profile_id,profile_version,state,revision FROM keygate.clients WHERE environment=$1 AND client_id=$2`, c.environment, id).Scan(&out.Environment, &out.ID, &out.Name, &out.Type, &out.ProfileID, &out.ProfileVersion, &out.State, &out.Revision)
	if e != nil {
		return access.Client{}, e
	}
	if e = tx.Commit(); e != nil {
		return access.Client{}, e
	}
	return out, nil
}

// EmergencyDisablePrincipal 只减权；本流程不能恢复身份或添加授权。
// 域锁使撤权与审批执行串行，停用立即影响旧会话，无需等待 Cookie 过期。
func (c *DevelopmentControl) EmergencyDisablePrincipal(ctx context.Context, token string, target, request string) error {
	if !identifier.MatchString(target) || !identifier.MatchString(request) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return e
	}
	// 身份影响整个环境，因此客户端级应急权限不能停用全域人员。
	if !c.has(ctx, tx, a.id, access.EmergencyOperator, "") {
		return ErrDenied
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.principals SET enabled=false,revision=revision+1 WHERE environment=$1 AND principal_id=$2 AND enabled`, c.environment, target)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if e = c.audit(ctx, tx, request, a.id, "principal_disable", target, "success"); e != nil {
		return e
	}
	return tx.Commit()
}

// 数据库时间由授权事务读取，禁止由外部请求指定审批创建或到期时间。
func controlNow(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	e := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now)
	return now, e
}
