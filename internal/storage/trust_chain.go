package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"ex-keygate/internal/access"
	"ex-keygate/trustchain"
	"time"
)

const PublishTrustCertificate = "trust_certificate_publish"
const DisableTrustService = "trust_service_disable"
const RenewTrustCertificate = "trust_certificate_renew"
const UpdateTrustStatusCertificate = "trust_status_update"

type ApplicationRoot struct {
	Info              *CertificateInfo `json:"info,omitempty"`
	StatusFingerprint string           `json:"statusFingerprint,omitempty"`
	Environment       string           `json:"applicationEnvironment"`
	Fingerprint       string           `json:"fingerprint"`
	Certificate       []byte           `json:"certificate"`
}
type TrustService struct {
	Info            *CertificateInfo `json:"info,omitempty"`
	RootFingerprint string           `json:"rootFingerprint"`
	ServiceID       string           `json:"serviceId"`
	Revision        uint64           `json:"revision"`
	Version         uint64           `json:"version"`
	Disabled        bool             `json:"disabled"`
	Certificate     []byte           `json:"certificate"`
	CertificateHash string           `json:"certificateHash"`
}

// RegisterApplicationRootOffline 只在可信启动阶段登记公有信任根；启用原生MFA后才允许接通业务签名模式。
func (c *DevelopmentControl) RegisterApplicationRootOffline(ctx context.Context, applicationEnvironment string, certificate []byte, trace string) error {
	if !access.ValidID(applicationEnvironment) || !access.ValidID(trace) {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var now time.Time
	var required bool
	if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp(),native_mfa_required FROM keygate.security_domains WHERE environment=$1`, c.environment).Scan(&now, &required); e != nil {
		return e
	}
	if !required {
		return ErrDenied
	}
	if _, e = trustchain.ParseRoot(certificate, now); e != nil {
		return ErrInvalid
	}
	previous, e := c.applicationRoot(ctx, tx, trustchain.Fingerprint(certificate))
	if e == nil {
		if previous.Fingerprint != trustchain.Fingerprint(certificate) || previous.Environment != applicationEnvironment {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_roots(environment,application_environment,fingerprint,certificate) VALUES($1,$2,$3,$4)`, c.environment, applicationEnvironment, trustchain.Fingerprint(certificate), certificate); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, "offline-operator", "application_trust_root_register", "trust-root", "success"); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *DevelopmentControl) applicationRoot(ctx context.Context, tx *sql.Tx, fingerprint string) (ApplicationRoot, error) {
	var r ApplicationRoot
	e := tx.QueryRowContext(ctx, `SELECT application_environment,fingerprint,certificate FROM keygate.application_trust_roots WHERE environment=$1 AND fingerprint=$2`, c.environment, fingerprint).Scan(&r.Environment, &r.Fingerprint, &r.Certificate)
	return r, e
}
func (c *DevelopmentControl) validateTrustOperation(ctx context.Context, tx *sql.Tx, op ControlOperation) error {
	// 独立字段集合防止把共享密钥、插件或恢复参数夹带进证书审批。
	copy := op
	copy.TrustCertificate = nil
	copy.TrustProof = nil
	copy.TrustRootFingerprint = ""
	copy.Kind = ""
	copy.ClientID = ""
	copy.ExpectedRevision = 0
	copy.KeyVersion = 0
	raw, _ := json.Marshal(copy)
	zero, _ := json.Marshal(ControlOperation{})
	if !bytes.Equal(raw, zero) {
		return ErrInvalid
	}
	root, e := c.applicationRoot(ctx, tx, op.TrustRootFingerprint)
	if e != nil {
		return e
	}
	if root.Fingerprint != op.TrustRootFingerprint || op.ExpectedRevision > 9007199254740991 || op.KeyVersion == 0 || op.KeyVersion > 9007199254740991 {
		return ErrInvalid
	}
	if op.Kind == UpdateTrustStatusCertificate {
		return c.validateStatusUpdate(ctx, tx, root, op)
	}
	var revision, version uint64
	var disabled bool
	var boundRoot string
	e = tx.QueryRowContext(ctx, `SELECT revision,active_version,disabled,root_fingerprint FROM keygate.application_trust_services WHERE environment=$1 AND service_id=$2`, c.environment, op.ClientID).Scan(&revision, &version, &disabled, &boundRoot)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	// 服务标识在管理域内唯一；换根必须走独立恢复，不能借普通轮换迁移信任。
	if revision > 0 && boundRoot != op.TrustRootFingerprint {
		return ErrConflict
	}
	if op.ExpectedRevision != revision {
		return ErrConflict
	}
	if op.Kind == DisableTrustService {
		if revision == 0 || disabled || op.KeyVersion != version || len(op.TrustCertificate) != 0 || len(op.TrustProof) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if op.Kind == RenewTrustCertificate && (revision == 0 || disabled) {
		return ErrConflict
	}
	if op.KeyVersion != version+1 {
		return ErrConflict
	}
	var now time.Time
	if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return e
	}
	pub, e := trustchain.VerifyCertificate(root.Certificate, op.TrustCertificate, root.Environment, trustchain.ServicePurpose, op.ClientID, op.KeyVersion, now)
	if e != nil || !trustchain.VerifyPossession(pub, op.TrustCertificate, op.TrustProof) {
		return ErrInvalid
	}
	if op.Kind == RenewTrustCertificate {
		old, err := c.trustService(ctx, tx, op.ClientID)
		if err != nil {
			return err
		}
		previous, err := certificateInfo(old.Certificate, now)
		next, nextErr := certificateInfo(op.TrustCertificate, now)
		// 续期只延长正常服务的有效期；泄漏、撤销及停用恢复必须走明确的新版本发布。
		if err != nil || nextErr != nil || !next.NotAfter.After(previous.NotAfter) {
			return ErrInvalid
		}
	}
	return nil
}
func (c *DevelopmentControl) applyTrustOperation(ctx context.Context, tx *sql.Tx, op ControlOperation, approvalID, actorID string) error {
	if op.Kind == UpdateTrustStatusCertificate {
		return c.applyStatusUpdate(ctx, tx, op, approvalID, actorID)
	}
	if op.Kind == DisableTrustService {
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.application_trust_services SET disabled=true,revision=revision+1 WHERE environment=$1 AND service_id=$2`, c.environment, op.ClientID); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.application_trust_certificates SET state='disabled' WHERE environment=$1 AND service_id=$2 AND state='active'`, c.environment, op.ClientID); e != nil {
			return e
		}
		return c.trustChange(ctx, tx, op.ClientID, op.KeyVersion, "disabled", "approved_disable", approvalID, actorID)
	}
	// 先记录被替代的活动版本；事务失败时事实与状态一起回滚。
	if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_changes(environment,root_fingerprint,service_id,version,revision,action,reason,approval_id,actor_id) SELECT s.environment,s.root_fingerprint,s.service_id,c.version,s.revision+1,'retired','replaced_by_new_version',$3,$4 FROM keygate.application_trust_services s JOIN keygate.application_trust_certificates c ON c.environment=s.environment AND c.service_id=s.service_id AND c.state='active' WHERE s.environment=$1 AND s.service_id=$2`, c.environment, op.ClientID, approvalID, actorID); e != nil {
		return e
	}
	// 新证书发布即切换当前版本，旧版本不再获发有效状态证明，泄露恢复不保留重叠窗口。
	if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_services(environment,service_id,revision,active_version,root_fingerprint) VALUES($1,$2,1,$3,$4) ON CONFLICT(environment,service_id) DO UPDATE SET revision=application_trust_services.revision+1,active_version=EXCLUDED.active_version,disabled=false`, c.environment, op.ClientID, op.KeyVersion, op.TrustRootFingerprint); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `UPDATE keygate.application_trust_certificates SET state='retired' WHERE environment=$1 AND service_id=$2 AND state='active'`, c.environment, op.ClientID); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_certificates(environment,service_id,version,fingerprint,certificate,state) VALUES($1,$2,$3,$4,$5,'active')`, c.environment, op.ClientID, op.KeyVersion, trustchain.Fingerprint(op.TrustCertificate), op.TrustCertificate); e != nil {
		return e
	}
	reason := "approved_publish"
	if op.Kind == RenewTrustCertificate {
		reason = "approved_renewal"
	}
	return c.trustChange(ctx, tx, op.ClientID, op.KeyVersion, "published", reason, approvalID, actorID)
}
func (c *DevelopmentControl) trustService(ctx context.Context, tx *sql.Tx, id string) (TrustService, error) {
	out := TrustService{ServiceID: id}
	e := tx.QueryRowContext(ctx, `SELECT s.revision,s.active_version,s.disabled,c.certificate,c.fingerprint,s.root_fingerprint FROM keygate.application_trust_services s JOIN keygate.application_trust_certificates c ON c.environment=s.environment AND c.service_id=s.service_id AND c.version=s.active_version WHERE s.environment=$1 AND s.service_id=$2`, c.environment, id).Scan(&out.Revision, &out.Version, &out.Disabled, &out.Certificate, &out.CertificateHash, &out.RootFingerprint)
	return out, e
}

// TrustStatusSnapshot 公开返回应用验签需要的元信息；必须读取权威库，数据库不可用时禁止缓存放行。
func (c *DevelopmentControl) TrustStatusSnapshot(ctx context.Context, id, trace string) (ApplicationRoot, TrustService, error) {
	if !access.ValidID(id) || !access.ValidID(trace) {
		return ApplicationRoot{}, TrustService{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return ApplicationRoot{}, TrustService{}, e
	}
	defer tx.Rollback()
	service, e := c.trustService(ctx, tx, id)
	if e != nil {
		return ApplicationRoot{}, service, e
	}
	root, e := c.applicationRoot(ctx, tx, service.RootFingerprint)
	if e != nil {
		return root, service, e
	}
	if e = c.audit(ctx, tx, trace, "public-verifier", "application_trust_status", id, "issued"); e != nil {
		return root, service, e
	}

	if e = tx.Commit(); e != nil {
		return root, service, e
	}
	return root, service, nil
}
func (c *DevelopmentControl) TrustServices(ctx context.Context, token string) ([]ApplicationRoot, []TrustService, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT service_id FROM keygate.application_trust_services WHERE environment=$1 ORDER BY service_id LIMIT 100`, c.environment)
	if e != nil {
		return nil, nil, e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return nil, nil, e
	}
	out := []TrustService{}
	for _, id := range ids {
		if !c.has(ctx, tx, a.id, access.Viewer, id) {
			continue
		}
		service, e := c.trustService(ctx, tx, id)
		if e != nil {
			return nil, nil, e
		}
		info, err := certificateInfo(service.Certificate, now)
		if err != nil {
			return nil, nil, err
		}
		service.Info = &info
		out = append(out, service)
	}
	if !c.has(ctx, tx, a.id, access.Viewer, "") && len(out) == 0 {
		return nil, nil, ErrDenied
	}
	// 全域查看者可见空根；范围查看者只看到有权服务关联的根，避免泄露其他业务目录。
	allRoots := []ApplicationRoot{}
	roots := []ApplicationRoot{}
	rootRows, e := tx.QueryContext(ctx, `SELECT application_environment,fingerprint,certificate FROM keygate.application_trust_roots WHERE environment=$1 ORDER BY fingerprint`, c.environment)
	if e != nil {
		return nil, nil, e
	}
	for rootRows.Next() {
		var root ApplicationRoot
		if e = rootRows.Scan(&root.Environment, &root.Fingerprint, &root.Certificate); e != nil {
			rootRows.Close()
			return nil, nil, e
		}
		allRoots = append(allRoots, root)
	}
	e = rootRows.Err()
	rootRows.Close()
	if e != nil {
		return nil, nil, e
	}
	globalViewer := c.has(ctx, tx, a.id, access.Viewer, "")
	for _, root := range allRoots {
		visible := globalViewer
		for _, service := range out {
			if service.RootFingerprint == root.Fingerprint {
				visible = true
				break
			}
		}
		if visible {
			info, err := certificateInfo(root.Certificate, now)
			if err != nil {
				return nil, nil, err
			}
			root.Info = &info
			roots = append(roots, root)
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, nil, e
	}
	return roots, out, nil
}

// RevokeTrustService 仅执行应急减权，提升修订并永久撤销当前版本；重新上线必须发布更高版本并重新审批。
func (c *DevelopmentControl) RevokeTrustService(ctx context.Context, token, id string, version uint64, reason, trace string) error {
	if !access.ValidID(id) || !access.ValidID(trace) || !validReason(reason) {
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
	if !c.has(ctx, tx, a.id, access.EmergencyOperator, id) {
		return ErrDenied
	}
	service, e := c.trustService(ctx, tx, id)
	if e != nil {
		return e
	}
	if service.Version != version {
		return ErrConflict
	}
	// 重试撤销不增加重复事实，也不改变最初的原因。
	var alreadyRevoked bool
	if e = tx.QueryRowContext(ctx, `SELECT state='revoked' FROM keygate.application_trust_certificates WHERE environment=$1 AND service_id=$2 AND version=$3`, c.environment, id, version).Scan(&alreadyRevoked); e != nil {
		return e
	}
	if alreadyRevoked {
		return tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.application_trust_services SET disabled=true,revision=revision+1 WHERE environment=$1 AND service_id=$2 AND NOT disabled`, c.environment, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.application_trust_certificates SET state='revoked' WHERE environment=$1 AND service_id=$2 AND version=$3`, c.environment, id, version); e != nil {
		return e
	}
	if e = c.trustChange(ctx, tx, id, version, "revoked", reason, "", a.id); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, a.id, "application_trust_revoke", id, "revoked"); e != nil {
		return e
	}
	return tx.Commit()
}

// IssueTrustStatus 签名在权威事务内完成，签名时间取数据库时间；提交失败不返回任何状态证明。
// 本接口只允许本机纯计算回调，避免快照提交后节点暂停再把过期状态签为全新状态。
func (c *DevelopmentControl) IssueTrustStatus(ctx context.Context, id, trace string, sign func(ApplicationRoot, TrustService, time.Time) (trustchain.Status, error)) (trustchain.Status, error) {
	if !access.ValidID(id) || !access.ValidID(trace) || sign == nil {
		return trustchain.Status{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return trustchain.Status{}, e
	}
	defer tx.Rollback()
	service, e := c.trustService(ctx, tx, id)
	if e != nil {
		return trustchain.Status{}, e
	}
	root, e := c.applicationRoot(ctx, tx, service.RootFingerprint)
	if e != nil {
		return trustchain.Status{}, e
	}
	if e = tx.QueryRowContext(ctx, `SELECT fingerprint FROM keygate.application_trust_status_signers WHERE environment=$1 AND root_fingerprint=$2`, c.environment, root.Fingerprint).Scan(&root.StatusFingerprint); e != nil {
		return trustchain.Status{}, e
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return trustchain.Status{}, e
	}
	out, e := sign(root, service, now)
	if e != nil {
		return trustchain.Status{}, e
	}
	if out.IssuedAt != now.Unix() || out.ExpiresAt > now.Unix()+30 || out.ExpiresAt <= now.Unix() || out.ServiceID != id || out.Environment != root.Environment || out.Revision != service.Revision || out.Version != service.Version || out.Disabled != service.Disabled || out.CertificateHash != service.CertificateHash {
		return trustchain.Status{}, ErrInvalid
	}
	// 已登记状态签名器后，只接受数据库当前批准的证书；旧节点不能绕过切换继续签发。
	var approved string
	err := tx.QueryRowContext(ctx, `SELECT fingerprint FROM keygate.application_trust_status_signers WHERE environment=$1 AND root_fingerprint=$2`, c.environment, root.Fingerprint).Scan(&approved)
	if err != nil || approved != trustchain.Fingerprint(out.StatusCertificate) {
		return trustchain.Status{}, ErrConflict
	}
	if e = c.audit(ctx, tx, trace, "public-verifier", "application_trust_status", id, "issued"); e != nil {
		return trustchain.Status{}, e
	}
	if e = tx.Commit(); e != nil {
		return trustchain.Status{}, e
	}
	return out, nil
}
