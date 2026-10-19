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

type ApplicationRoot struct {
	Environment string `json:"applicationEnvironment"`
	Fingerprint string `json:"fingerprint"`
	Certificate []byte `json:"certificate"`
}
type TrustService struct {
	ServiceID       string `json:"serviceId"`
	Revision        uint64 `json:"revision"`
	Version         uint64 `json:"version"`
	Disabled        bool   `json:"disabled"`
	Certificate     []byte `json:"certificate"`
	CertificateHash string `json:"certificateHash"`
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
	previous, e := c.applicationRoot(ctx, tx)
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
func (c *DevelopmentControl) applicationRoot(ctx context.Context, tx *sql.Tx) (ApplicationRoot, error) {
	var r ApplicationRoot
	e := tx.QueryRowContext(ctx, `SELECT application_environment,fingerprint,certificate FROM keygate.application_trust_roots WHERE environment=$1`, c.environment).Scan(&r.Environment, &r.Fingerprint, &r.Certificate)
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
	root, e := c.applicationRoot(ctx, tx)
	if e != nil {
		return e
	}
	if root.Fingerprint != op.TrustRootFingerprint || op.ExpectedRevision > 9007199254740991 || op.KeyVersion == 0 || op.KeyVersion > 9007199254740991 {
		return ErrInvalid
	}
	var revision, version uint64
	var disabled bool
	e = tx.QueryRowContext(ctx, `SELECT revision,active_version,disabled FROM keygate.application_trust_services WHERE environment=$1 AND service_id=$2`, c.environment, op.ClientID).Scan(&revision, &version, &disabled)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
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
	return nil
}
func (c *DevelopmentControl) applyTrustOperation(ctx context.Context, tx *sql.Tx, op ControlOperation) error {
	if op.Kind == DisableTrustService {
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.application_trust_services SET disabled=true,revision=revision+1 WHERE environment=$1 AND service_id=$2`, c.environment, op.ClientID); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `UPDATE keygate.application_trust_certificates SET state='disabled' WHERE environment=$1 AND service_id=$2 AND state='active'`, c.environment, op.ClientID)
		return e
	}
	// 新证书发布即切换当前版本，旧版本不再获发有效状态证明，泄露恢复不保留重叠窗口。
	if _, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_services(environment,service_id,revision,active_version) VALUES($1,$2,1,$3) ON CONFLICT(environment,service_id) DO UPDATE SET revision=application_trust_services.revision+1,active_version=EXCLUDED.active_version,disabled=false`, c.environment, op.ClientID, op.KeyVersion); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `UPDATE keygate.application_trust_certificates SET state='retired' WHERE environment=$1 AND service_id=$2 AND state='active'`, c.environment, op.ClientID); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_certificates(environment,service_id,version,fingerprint,certificate,state) VALUES($1,$2,$3,$4,$5,'active')`, c.environment, op.ClientID, op.KeyVersion, trustchain.Fingerprint(op.TrustCertificate), op.TrustCertificate)
	return e
}
func (c *DevelopmentControl) trustService(ctx context.Context, tx *sql.Tx, id string) (TrustService, error) {
	out := TrustService{ServiceID: id}
	e := tx.QueryRowContext(ctx, `SELECT s.revision,s.active_version,s.disabled,c.certificate,c.fingerprint FROM keygate.application_trust_services s JOIN keygate.application_trust_certificates c ON c.environment=s.environment AND c.service_id=s.service_id AND c.version=s.active_version WHERE s.environment=$1 AND s.service_id=$2`, c.environment, id).Scan(&out.Revision, &out.Version, &out.Disabled, &out.Certificate, &out.CertificateHash)
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
	root, e := c.applicationRoot(ctx, tx)
	if e != nil {
		return root, TrustService{}, e
	}
	service, e := c.trustService(ctx, tx, id)
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
func (c *DevelopmentControl) TrustServices(ctx context.Context, token string) (ApplicationRoot, []TrustService, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return ApplicationRoot{}, nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return ApplicationRoot{}, nil, e
	}
	root, e := c.applicationRoot(ctx, tx)
	if e != nil {
		return root, nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT service_id FROM keygate.application_trust_services WHERE environment=$1 ORDER BY service_id LIMIT 100`, c.environment)
	if e != nil {
		return root, nil, e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return root, nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return root, nil, e
	}
	out := []TrustService{}
	for _, id := range ids {
		if !c.has(ctx, tx, a.id, access.Viewer, id) {
			continue
		}
		service, e := c.trustService(ctx, tx, id)
		if e != nil {
			return root, nil, e
		}
		out = append(out, service)
	}
	if !c.has(ctx, tx, a.id, access.Viewer, "") && len(out) == 0 {
		return root, nil, ErrDenied
	}
	if e = tx.Commit(); e != nil {
		return root, nil, e
	}
	return root, out, nil
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
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.application_trust_services SET disabled=true,revision=revision+1 WHERE environment=$1 AND service_id=$2 AND NOT disabled`, c.environment, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.application_trust_certificates SET state='revoked' WHERE environment=$1 AND service_id=$2 AND version=$3`, c.environment, id, version); e != nil {
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
	root, e := c.applicationRoot(ctx, tx)
	if e != nil {
		return trustchain.Status{}, e
	}
	service, e := c.trustService(ctx, tx, id)
	if e != nil {
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
	if e = c.audit(ctx, tx, trace, "public-verifier", "application_trust_status", id, "issued"); e != nil {
		return trustchain.Status{}, e
	}
	if e = tx.Commit(); e != nil {
		return trustchain.Status{}, e
	}
	return out, nil
}
