package storage

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"ex-keygate/internal/access"
	"ex-keygate/trustchain"
	"strconv"
	"time"
)

type CertificateInfo struct {
	Fingerprint        string    `json:"fingerprint"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	Algorithm          string    `json:"algorithm"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	IsCA               bool      `json:"isCA"`
	KeyUsage           int       `json:"keyUsage"`
	ExtendedKeyUsage   []int     `json:"extendedKeyUsage"`
	URIs               []string  `json:"uris"`
	Validity           string    `json:"validity"`
}
type TrustChange struct {
	Sequence   int64     `json:"sequence,string"`
	Version    uint64    `json:"version"`
	Revision   uint64    `json:"revision"`
	Action     string    `json:"action"`
	Reason     string    `json:"reason"`
	ApprovalID string    `json:"approvalId"`
	ActorID    string    `json:"actorId"`
	RecordedAt time.Time `json:"recordedAt"`
}
type TrustApprovalLink struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Decision    string `json:"decision"`
	Executed    bool   `json:"executed"`
	ApplicantID string `json:"applicantId"`
	CreatedAt   string `json:"createdAt"`
}
type TrustCertificate struct {
	Version uint64          `json:"version"`
	State   string          `json:"state"`
	Current bool            `json:"current"`
	Info    CertificateInfo `json:"info"`
}
type TrustCertificateHistory struct {
	Certificates []TrustCertificate `json:"certificates"`
	HasMore      bool               `json:"hasMore"`
	NextBefore   uint64             `json:"nextBefore"`
}
type TrustCertificateDetail struct {
	Service                TrustService        `json:"service"`
	Root                   ApplicationRoot     `json:"root"`
	RootInfo               CertificateInfo     `json:"rootInfo"`
	Certificate            TrustCertificate    `json:"certificate"`
	ChainValid             bool                `json:"chainValid"`
	AuthenticationEligible bool                `json:"authenticationEligible"`
	Changes                []TrustChange       `json:"changes"`
	Approvals              []TrustApprovalLink `json:"approvals"`
	ChangesHasMore         bool                `json:"changesHasMore"`
	ApprovalsHasMore       bool                `json:"approvalsHasMore"`
}

func certificateInfo(der []byte, now time.Time) (CertificateInfo, error) {
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		return CertificateInfo{}, ErrInvalid
	}
	validity := "valid"
	if now.Before(cert.NotBefore) {
		validity = "not_yet_valid"
	} else if !now.Before(cert.NotAfter) {
		validity = "expired"
	}
	out := CertificateInfo{Fingerprint: trustchain.Fingerprint(der), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), Serial: cert.SerialNumber.Text(16), Algorithm: cert.PublicKeyAlgorithm.String(), SignatureAlgorithm: cert.SignatureAlgorithm.String(), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, IsCA: cert.IsCA, KeyUsage: int(cert.KeyUsage), ExtendedKeyUsage: []int{}, URIs: []string{}, Validity: validity}
	for _, usage := range cert.ExtKeyUsage {
		out.ExtendedKeyUsage = append(out.ExtendedKeyUsage, int(usage))
	}
	for _, uri := range cert.URIs {
		out.URIs = append(out.URIs, uri.String())
	}
	return out, nil
}
func validFingerprint(fp string) bool {
	b, e := hex.DecodeString(fp)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == fp
}

// trustRead 同事务检查会话、原生MFA、人员启用状态及当前服务查看权限；不得从页面参数推导权限。
func (c *DevelopmentControl) trustRead(ctx context.Context, tx *sql.Tx, token, id string) (controlActor, error) {
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return a, e
	}
	if !c.has(ctx, tx, a.id, access.Viewer, id) {
		return a, ErrDenied
	}
	return a, nil
}
func (c *DevelopmentControl) trustChange(ctx context.Context, tx *sql.Tx, id string, version uint64, action, reason, approval, actor string) error {
	_, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_changes(environment,root_fingerprint,service_id,version,revision,action,reason,approval_id,actor_id) SELECT environment,root_fingerprint,service_id,$3,revision,$4,$5,$6,$7 FROM keygate.application_trust_services WHERE environment=$1 AND service_id=$2`, c.environment, id, version, action, reason, approval, actor)
	return e
}

func (c *DevelopmentControl) TrustCertificateHistory(ctx context.Context, token, id string, before uint64, limit int) (TrustCertificateHistory, error) {
	out := TrustCertificateHistory{Certificates: []TrustCertificate{}}
	if !access.ValidID(id) || before > 9007199254740991 || limit < 1 || limit > 50 {
		return out, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if _, e = c.trustRead(ctx, tx, token, id); e != nil {
		return out, e
	}
	service, e := c.trustService(ctx, tx, id)
	if e != nil {
		return out, e
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT version,state,certificate FROM keygate.application_trust_certificates WHERE environment=$1 AND service_id=$2 AND ($3::bigint=0 OR version<$3) ORDER BY version DESC LIMIT $4`, c.environment, id, before, limit+1)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var cert TrustCertificate
		var der []byte
		if e = rows.Scan(&cert.Version, &cert.State, &der); e != nil {
			rows.Close()
			return out, e
		}
		cert.Current = cert.Version == service.Version
		cert.Info, e = certificateInfo(der, now)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Certificates = append(out.Certificates, cert)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	if len(out.Certificates) > limit {
		out.HasMore = true
		out.Certificates = out.Certificates[:limit]
		out.NextBefore = out.Certificates[limit-1].Version
	}
	if e = tx.Commit(); e != nil {
		return TrustCertificateHistory{}, e
	}
	return out, nil
}

// TrustCertificateDetail 只返回公开元数据和限定服务/版本的变更，过期证书仍可查阅，但不能据此重新获得认证资格。
func (c *DevelopmentControl) TrustCertificateDetail(ctx context.Context, token, id string, version uint64, download bool, trace string) (TrustCertificateDetail, []byte, error) {
	var out TrustCertificateDetail
	if !access.ValidID(id) || version == 0 || version > 9007199254740991 || !access.ValidID(trace) {
		return out, nil, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, nil, e
	}
	defer tx.Rollback()
	a, e := c.trustRead(ctx, tx, token, id)
	if e != nil {
		return out, nil, e
	}
	out.Service, e = c.trustService(ctx, tx, id)
	if e != nil {
		return out, nil, e
	}
	out.Root, e = c.applicationRoot(ctx, tx, out.Service.RootFingerprint)
	if e != nil {
		return out, nil, e
	}
	var der []byte
	out.Certificate.Version = version
	out.Certificate.Current = version == out.Service.Version
	if e = tx.QueryRowContext(ctx, `SELECT state,certificate FROM keygate.application_trust_certificates WHERE environment=$1 AND service_id=$2 AND version=$3`, c.environment, id, version).Scan(&out.Certificate.State, &der); e != nil {
		return out, nil, e
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return out, nil, e
	}
	out.RootInfo, e = certificateInfo(out.Root.Certificate, now)
	if e != nil {
		return out, nil, e
	}
	out.Certificate.Info, e = certificateInfo(der, now)
	if e != nil {
		return out, nil, e
	}
	// 将签名/用途完整性与当前有效期分开，避免把过期历史显示为被篡改，或把签名正确误作当前可认证。
	checkAt := out.Certificate.Info.NotBefore
	if out.RootInfo.NotBefore.After(checkAt) {
		checkAt = out.RootInfo.NotBefore
	}
	_, chainErr := trustchain.VerifyCertificate(out.Root.Certificate, der, out.Root.Environment, trustchain.ServicePurpose, id, version, checkAt)
	out.ChainValid = chainErr == nil
	out.AuthenticationEligible = out.ChainValid && out.Certificate.Current && !out.Service.Disabled && out.Certificate.State == "active" && out.Certificate.Info.Validity == "valid" && out.RootInfo.Validity == "valid"
	out.Changes = []TrustChange{}
	out.Approvals = []TrustApprovalLink{}
	if !download {
		rows, e := tx.QueryContext(ctx, `SELECT sequence,version,revision,action,reason,approval_id,actor_id,recorded_at FROM keygate.application_trust_changes WHERE environment=$1 AND service_id=$2 AND version=$3 AND root_fingerprint=$4 ORDER BY sequence DESC LIMIT 101`, c.environment, id, version, out.Root.Fingerprint)
		if e != nil {
			return out, nil, e
		}
		for rows.Next() {
			var change TrustChange
			if e = rows.Scan(&change.Sequence, &change.Version, &change.Revision, &change.Action, &change.Reason, &change.ApprovalID, &change.ActorID, &change.RecordedAt); e != nil {
				rows.Close()
				return out, nil, e
			}
			out.Changes = append(out.Changes, change)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, nil, e
		}
		if len(out.Changes) > 100 {
			out.ChangesHasMore = true
			out.Changes = out.Changes[:100]
		}
		rows, e = tx.QueryContext(ctx, `SELECT request_id,decision,executed,applicant_id,convert_from(manifest,'UTF8')::jsonb->'operation'->>'kind',convert_from(manifest,'UTF8')::jsonb->>'created' FROM keygate.control_requests WHERE environment=$1 AND convert_from(manifest,'UTF8')::jsonb->'operation'->>'clientId'=$2 AND convert_from(manifest,'UTF8')::jsonb->'operation'->>'keyVersion'=$3 AND convert_from(manifest,'UTF8')::jsonb->'operation'->>'trustRootFingerprint'=$4 ORDER BY convert_from(manifest,'UTF8')::jsonb->>'created' DESC,request_id DESC LIMIT 101`, c.environment, id, strconv.FormatUint(version, 10), out.Root.Fingerprint)
		if e != nil {
			return out, nil, e
		}
		for rows.Next() {
			var link TrustApprovalLink
			if e = rows.Scan(&link.ID, &link.Decision, &link.Executed, &link.ApplicantID, &link.Kind, &link.CreatedAt); e != nil {
				rows.Close()
				return out, nil, e
			}
			out.Approvals = append(out.Approvals, link)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, nil, e
		}
		if len(out.Approvals) > 100 {
			out.ApprovalsHasMore = true
			out.Approvals = out.Approvals[:100]
		}
	}
	if download {
		if e = c.audit(ctx, tx, trace, a.id, "application_trust_certificate_download", id, "success"); e != nil {
			return TrustCertificateDetail{}, nil, e
		}
	}
	if e = tx.Commit(); e != nil {
		return TrustCertificateDetail{}, nil, e
	}
	return out, der, nil
}

// TrustRootDetail 范围查看者只能读取其有权服务关联的根；不能通过猜根指纹遍历其他业务。
func (c *DevelopmentControl) TrustRootDetail(ctx context.Context, token, fp string, download bool, trace string) (ApplicationRoot, CertificateInfo, error) {
	var root ApplicationRoot
	var info CertificateInfo
	if !validFingerprint(fp) || !access.ValidID(trace) {
		return root, info, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return root, info, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return root, info, e
	}
	allowed := c.has(ctx, tx, a.id, access.Viewer, "")
	if !allowed {
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.application_trust_services s JOIN keygate.role_grants g ON g.environment=s.environment AND g.client_id=s.service_id WHERE s.environment=$1 AND s.root_fingerprint=$2 AND g.principal_id=$3 AND g.role='viewer' AND g.enabled)`, c.environment, fp, a.id).Scan(&allowed); e != nil {
			return root, info, e
		}
	}
	if !allowed {
		return root, info, ErrDenied
	}
	root, e = c.applicationRoot(ctx, tx, fp)
	if e != nil {
		return root, info, e
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return root, info, e
	}
	info, e = certificateInfo(root.Certificate, now)
	if e != nil {
		return root, info, e
	}
	if download {
		if e = c.audit(ctx, tx, trace, a.id, "application_trust_root_download", fp, "success"); e != nil {
			return ApplicationRoot{}, CertificateInfo{}, e
		}
	}
	if e = tx.Commit(); e != nil {
		return ApplicationRoot{}, CertificateInfo{}, e
	}
	return root, info, nil
}
