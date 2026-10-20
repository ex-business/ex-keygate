package storage

import (
	"context"
	"crypto/x509"
	"database/sql"
	"ex-keygate/internal/access"
	"ex-keygate/trustchain"
	"time"
)

type TrustStatusChange struct {
	Revision    uint64    `json:"revision"`
	Fingerprint string    `json:"fingerprint"`
	ApprovalID  string    `json:"approvalId"`
	ActorID     string    `json:"actorId"`
	RecordedAt  time.Time `json:"recordedAt"`
}
type TrustStatusSigner struct {
	Changes        []TrustStatusChange `json:"changes"`
	ChangesHasMore bool                `json:"changesHasMore"`

	RootFingerprint string          `json:"rootFingerprint"`
	Revision        uint64          `json:"revision"`
	Certificate     []byte          `json:"certificate"`
	Info            CertificateInfo `json:"info"`
}

// RegisterTrustStatusOffline 仅首次可信启动登记；重启或候选材料不能覆盖已有审批指针。
func (c *DevelopmentControl) RegisterTrustStatusOffline(ctx context.Context, rootFP string, cert []byte, trace string) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	root, e := c.applicationRoot(ctx, tx, rootFP)
	if e != nil {
		return e
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return e
	}
	if _, e = trustchain.VerifyCertificate(root.Certificate, cert, root.Environment, trustchain.StatusPurpose, "trust-status", 1, now); e != nil {
		return ErrInvalid
	}
	result, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_status_signers(environment,root_fingerprint,revision,fingerprint,certificate) VALUES($1,$2,1,$3,$4) ON CONFLICT DO NOTHING`, c.environment, rootFP, trustchain.Fingerprint(cert), cert)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n == 1 {
		if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_status_changes(environment,root_fingerprint,revision,fingerprint,certificate,approval_id,actor_id) VALUES($1,$2,1,$3,$4,'','offline-operator')`, c.environment, rootFP, trustchain.Fingerprint(cert), cert); e != nil {
			return e
		}
		if e = c.audit(ctx, tx, trace, "offline-operator", "application_trust_status_bootstrap", rootFP, "success"); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (c *DevelopmentControl) statusSigner(ctx context.Context, tx *sql.Tx, fp string) (TrustStatusSigner, error) {
	out := TrustStatusSigner{RootFingerprint: fp}
	e := tx.QueryRowContext(ctx, `SELECT revision,certificate FROM keygate.application_trust_status_signers WHERE environment=$1 AND root_fingerprint=$2`, c.environment, fp).Scan(&out.Revision, &out.Certificate)
	if e != nil {
		return out, e
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return out, e
	}
	out.Info, e = certificateInfo(out.Certificate, now)
	return out, e
}
func (c *DevelopmentControl) validateStatusUpdate(ctx context.Context, tx *sql.Tx, root ApplicationRoot, op ControlOperation) error {
	if op.ClientID != "trust-status" || op.KeyVersion != 1 {
		return ErrInvalid
	}
	current, e := c.statusSigner(ctx, tx, root.Fingerprint)
	if e != nil {
		return e
	}
	if op.ExpectedRevision != current.Revision {
		return ErrConflict
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return e
	}
	pub, e := trustchain.VerifyCertificate(root.Certificate, op.TrustCertificate, root.Environment, trustchain.StatusPurpose, "trust-status", 1, now)
	if e != nil || !trustchain.VerifyPossession(pub, op.TrustCertificate, op.TrustProof) {
		return ErrInvalid
	}
	info, e := certificateInfo(op.TrustCertificate, now)
	if e != nil {
		return e
	}
	// 拒绝指纹重用与旧密钥回退；新的状态证书必须延长有效期。
	if !info.NotAfter.After(current.Info.NotAfter) {
		return ErrInvalid
	}
	// 更新状态签名器必须使用新密钥；不能将历史密钥包装成更晚到期的证书重新启用。
	rows, e := tx.QueryContext(ctx, `SELECT certificate FROM keygate.application_trust_status_changes WHERE environment=$1 AND root_fingerprint=$2`, c.environment, root.Fingerprint)
	if e != nil {
		return e
	}
	reused := false
	for rows.Next() {
		var der []byte
		if e = rows.Scan(&der); e != nil {
			rows.Close()
			return e
		}
		previous, err := x509.ParseCertificate(der)
		if err != nil {
			rows.Close()
			return ErrInvalid
		}
		if pub.Equal(previous.PublicKey) {
			reused = true
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if reused {
		return ErrInvalid
	}
	var exists bool
	e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.application_trust_status_changes WHERE environment=$1 AND root_fingerprint=$2 AND fingerprint=$3)`, c.environment, root.Fingerprint, info.Fingerprint).Scan(&exists)
	if e != nil {
		return e
	}
	if exists {
		return ErrConflict
	}
	return nil
}
func (c *DevelopmentControl) applyStatusUpdate(ctx context.Context, tx *sql.Tx, op ControlOperation, approval, actor string) error {
	if _, e := tx.ExecContext(ctx, `UPDATE keygate.application_trust_status_signers SET revision=revision+1,fingerprint=$3,certificate=$4 WHERE environment=$1 AND root_fingerprint=$2`, c.environment, op.TrustRootFingerprint, trustchain.Fingerprint(op.TrustCertificate), op.TrustCertificate); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_status_changes(environment,root_fingerprint,revision,fingerprint,certificate,approval_id,actor_id) SELECT environment,root_fingerprint,revision,fingerprint,certificate,$3,$4 FROM keygate.application_trust_status_signers WHERE environment=$1 AND root_fingerprint=$2`, c.environment, op.TrustRootFingerprint, approval, actor)
	return e
}

// TrustStatusSigners 仅全域查看者可读，避免范围账号获取其他业务的共享运行材料目录。
func (c *DevelopmentControl) TrustStatusSigners(ctx context.Context, token string) ([]TrustStatusSigner, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	if !c.has(ctx, tx, a.id, access.Viewer, "") {
		return nil, ErrDenied
	}
	rows, e := tx.QueryContext(ctx, `SELECT root_fingerprint FROM keygate.application_trust_status_signers WHERE environment=$1 ORDER BY root_fingerprint`, c.environment)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []TrustStatusSigner{}
	for _, id := range ids {
		v, e := c.statusSigner(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		history, e := tx.QueryContext(ctx, `SELECT revision,fingerprint,approval_id,actor_id,recorded_at FROM keygate.application_trust_status_changes WHERE environment=$1 AND root_fingerprint=$2 ORDER BY revision DESC LIMIT 51`, c.environment, id)
		if e != nil {
			return nil, e
		}
		v.Changes = []TrustStatusChange{}
		for history.Next() {
			var change TrustStatusChange
			if e = history.Scan(&change.Revision, &change.Fingerprint, &change.ApprovalID, &change.ActorID, &change.RecordedAt); e != nil {
				history.Close()
				return nil, e
			}
			v.Changes = append(v.Changes, change)
		}
		e = history.Err()
		history.Close()
		if e != nil {
			return nil, e
		}
		if len(v.Changes) > 50 {
			v.Changes = v.Changes[:50]
			v.ChangesHasMore = true
		}
		out = append(out, v)
	}
	return out, tx.Commit()
}
