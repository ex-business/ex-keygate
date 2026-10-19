package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"strconv"
	"time"

	"ex-keygate/internal/access"
	"ex-keygate/internal/keycrypto"
	"ex-keygate/internal/manifest"
)

type preparedKey struct {
	issueID, digest                                               string
	envelope                                                      keycrypto.Envelope
	delivery, recipient, signingRecipient, claimNonce, proofNonce []byte
}
type DevelopmentKeys struct {
	control     *DevelopmentControl
	rootID      string
	wrapper     *keycrypto.Wrapper
	fingerprint string
}

// NewDevelopmentKeys 仅接受专用客户端根，不能复用登录 PKCE 根；两者均由可信启动配置提供。
// 此具体类型只执行本地软件运算，不接受可能产生远程副作用的插件替换。
func NewDevelopmentKeys(c *DevelopmentControl, rootID string, key []byte, loginRootID string) (*DevelopmentKeys, error) {
	if c == nil || !access.ValidID(loginRootID) || rootID == loginRootID {
		return nil, ErrInvalid
	}
	w, e := keycrypto.New(rootID, key)
	if e != nil {
		return nil, e
	}
	return &DevelopmentKeys{c, rootID, w, digestBytes(key)}, nil
}
func (k *DevelopmentKeys) RegisterRootOffline(ctx context.Context, trace string) error {
	if !access.ValidID(trace) {
		return ErrInvalid
	}
	c := k.control
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.client_roots(root_id,environment,purpose,key_fingerprint) VALUES($1,$2,'client_auth',$3)`, k.rootID, c.environment, k.fingerprint); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, "offline-bootstrap", "client_root_register", k.rootID, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
func recipientKey(encoded, fingerprint string) (*rsa.PublicKey, []byte, error) {
	der, e := base64.RawStdEncoding.DecodeString(encoded)
	if e != nil || len(der) > 1024 || base64.RawStdEncoding.EncodeToString(der) != encoded {
		return nil, nil, ErrInvalid
	}
	parsed, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return nil, nil, ErrInvalid
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok || (pub.N.BitLen() != 3072 && pub.N.BitLen() != 4096) || pub.E != 65537 || digestBytes(der) != fingerprint {
		return nil, nil, ErrInvalid
	}
	return pub, der, nil
}
func exactTime(raw string) (time.Time, error) {
	t, e := time.Parse("2006-01-02T15:04:05.000Z", raw)
	if e != nil || t.Format("2006-01-02T15:04:05.000Z") != raw {
		return time.Time{}, ErrInvalid
	}
	return t, e
}
func (c *DevelopmentControl) validateKeyOperation(ctx context.Context, tx *sql.Tx, op ControlOperation) error {
	if op.ExpectedRevision == 0 || op.KeyVersion == 0 || op.KeyVersion > 9007199254740991 || op.Name != "" || op.ProfileID != "" || op.ProfileVersion != 0 {
		return ErrInvalid
	}
	var revision uint64
	var state, method, provider string
	var profileEnabled bool
	e := tx.QueryRowContext(ctx, `SELECT c.revision,c.state,p.method,p.provider_id,p.enabled FROM keygate.clients c JOIN keygate.auth_profiles p ON p.environment=c.environment AND p.profile_id=c.profile_id AND p.version=c.profile_version WHERE c.environment=$1 AND c.client_id=$2`, c.environment, op.ClientID).Scan(&revision, &state, &method, &provider, &profileEnabled)
	if e != nil {
		return e
	}
	if revision != op.ExpectedRevision {
		return ErrConflict
	}
	if op.Kind != DisableKey && (state != "enabled" || !profileEnabled || method != "hmac_sha256" || provider != "internal-software") {
		return ErrDenied
	}
	now, e := controlNow(ctx, tx)
	if e != nil {
		return e
	}
	switch op.Kind {
	case IssueKey:
		if !access.ValidID(op.RootID) || op.RetireAt != "" {
			return ErrInvalid
		}
		if _, _, e = recipientKey(op.RecipientPublicKey, op.RecipientFingerprint); e != nil {
			return e
		}
		if e = c.rootEnabled(ctx, tx, op.RootID); e != nil {
			return e
		}
		if _, _, e = recipientSigningKey(op.RecipientSigningKey, op.RecipientSigningFingerprint); e != nil {
			return e
		}
		expires, e := exactTime(op.NotAfter)
		if e != nil || !expires.After(now) || expires.After(now.Add(24*time.Hour)) {
			return ErrInvalid
		}
		var next uint64
		e = tx.QueryRowContext(ctx, `SELECT COALESCE(max(version),0)+1 FROM keygate.key_versions WHERE environment=$1 AND client_id=$2`, c.environment, op.ClientID).Scan(&next)
		if e != nil {
			return e
		}
		if op.KeyVersion != next {
			return ErrConflict
		}
	case ActivateKey, DisableKey:
		if op.RecipientSigningKey != "" || op.RecipientSigningFingerprint != "" || op.RootID != "" || op.NotAfter != "" || op.RecipientPublicKey != "" || op.RecipientFingerprint != "" {
			return ErrInvalid
		}
		var keyState string
		var before, after time.Time
		var claimed bool
		var rootEnabled bool
		e = tx.QueryRowContext(ctx, `SELECT k.state,k.not_before,k.not_after,k.claimed_at IS NOT NULL,r.enabled FROM keygate.key_versions k JOIN keygate.client_roots r ON r.environment=k.environment AND r.root_id=k.root_id WHERE k.environment=$1 AND k.client_id=$2 AND k.version=$3`, c.environment, op.ClientID, op.KeyVersion).Scan(&keyState, &before, &after, &claimed, &rootEnabled)
		if e != nil {
			return e
		}
		if op.Kind == DisableKey {
			if op.RetireAt != "" || keyState == "disabled" || keyState == "compromised" {
				return ErrConflict
			}
			return nil
		}
		if keyState != "staged" || !claimed || !rootEnabled || now.Before(before) || !now.Before(after) {
			return ErrConflict
		}
		var active, retiring int
		e = tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state='active' AND not_after>clock_timestamp()),count(*) FILTER(WHERE state='retiring' AND not_after>clock_timestamp()) FROM keygate.key_versions WHERE environment=$1 AND client_id=$2`, c.environment, op.ClientID).Scan(&active, &retiring)
		if e != nil {
			return e
		}
		if retiring > 0 {
			return ErrConflict
		}
		if active > 0 {
			retire, e := exactTime(op.RetireAt)
			if e != nil || !retire.After(now) || retire.After(now.Add(15*time.Minute)) {
				return ErrInvalid
			}
		} else if op.RetireAt != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func (c *DevelopmentControl) rootEnabled(ctx context.Context, tx *sql.Tx, root string) error {
	var enabled bool
	e := tx.QueryRowContext(ctx, `SELECT enabled FROM keygate.client_roots WHERE environment=$1 AND root_id=$2 AND purpose='client_auth'`, c.environment, root).Scan(&enabled)
	if e != nil {
		return e
	}
	if !enabled {
		return ErrDenied
	}
	return nil
}

// ExecuteIssue 先验证授权，再在独立事务消耗预算，最后重新校验并提交本地结果。
// 竞争或撤权导致结果丢弃仍消耗预算；不退款，不把软件预计算误当远程幂等副作用。
func (k *DevelopmentKeys) ExecuteIssue(ctx context.Context, id, digest, trace string) error {
	c := k.control
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
	if r.Digest != digest {
		return ErrConflict
	}
	if r.Executed {
		return tx.Commit()
	}
	if r.Decision != "approved" || m.Operation.Kind != IssueKey || m.Operation.RootID != k.rootID {
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
	if e = k.rootMatches(ctx, tx); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	event, e := controlID()
	if e != nil {
		return e
	}
	if e = c.store.ReserveWrappingUse(ctx, k.rootID, Audit{event, trace, "executor-service", "root_wrap_reserve", k.rootID, "reserved"}); e != nil {
		return e
	}
	secret, e := keycrypto.Generate()
	if e != nil {
		return e
	}
	defer clear(secret)
	op := m.Operation
	b := keycrypto.Binding{Environment: c.environment, ClientID: op.ClientID, KeyID: op.ClientID, Version: op.KeyVersion, Purpose: "client_auth"}
	envelope, e := k.wrapper.Seal(b, secret)
	if e != nil {
		return e
	}
	pub, der, e := recipientKey(op.RecipientPublicKey, op.RecipientFingerprint)
	if e != nil {
		return e
	}
	// OAEP 标签绑定申请与目标，不允许把交付密文搬到另一客户端或版本。
	label, e := deliveryInput(c.environment, op.ClientID, op.KeyVersion, id, op.RecipientFingerprint, op.RecipientSigningFingerprint, "keygate-delivery-wrap-v1", nil)
	if e != nil {
		return e
	}
	encrypted, e := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, secret, label)
	if e != nil {
		return e
	}
	_, signingDER, e := recipientSigningKey(op.RecipientSigningKey, op.RecipientSigningFingerprint)
	if e != nil {
		return e
	}
	p := preparedKey{issueID: id, digest: digest, envelope: envelope, delivery: encrypted, recipient: der, signingRecipient: signingDER, claimNonce: make([]byte, 32), proofNonce: make([]byte, 32)}
	if _, e = rand.Read(p.claimNonce); e != nil {
		return e
	}
	if _, e = rand.Read(p.proofNonce); e != nil {
		return e
	}
	return c.executePrepared(ctx, id, digest, trace, &p)
}
func (c *DevelopmentControl) applyKeyOperation(ctx context.Context, tx *sql.Tx, m controlManifest, p *preparedKey) error {
	op := m.Operation
	switch op.Kind {
	case IssueKey:
		if p == nil || p.issueID != m.RequestID || p.digest != digestBytesMust(m) || p.envelope.RootID != op.RootID {
			return ErrDenied
		}
		if e := c.rootEnabled(ctx, tx, p.envelope.RootID); e != nil {
			return e
		}
		expires, _ := exactTime(op.NotAfter)
		_, e := tx.ExecContext(ctx, `INSERT INTO keygate.key_versions(environment,client_id,version,state,root_id,format,ciphertext,not_before,not_after,issue_id,recipient_der,recipient_fingerprint,delivery_ciphertext,claim_nonce,proof_nonce,claim_expires,recipient_signing_der,recipient_signing_fingerprint)
 VALUES($1,$2,$3,'pending',$4,$5,$6,clock_timestamp(),$7,$8,$9,$10,$11,$12,$13,LEAST($7,clock_timestamp()+interval '5 minutes'),$14,$15)`, c.environment, op.ClientID, op.KeyVersion, p.envelope.RootID, p.envelope.Format, p.envelope.Ciphertext, expires, m.RequestID, p.recipient, op.RecipientFingerprint, p.delivery, p.claimNonce, p.proofNonce, p.signingRecipient, op.RecipientSigningFingerprint)
		if e != nil {
			return e
		}
	case ActivateKey:
		// 先清理已按时间失效的状态占位，再原子切换旧新版本，避免多个 ACTIVE 或 RETIRING。
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='expired' WHERE environment=$1 AND client_id=$2 AND state IN ('active','retiring') AND not_after<=clock_timestamp()`, c.environment, op.ClientID); e != nil {
			return e
		}
		if op.RetireAt != "" {
			retire, _ := exactTime(op.RetireAt)
			if _, e := tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='retiring',not_after=LEAST(not_after,$3) WHERE environment=$1 AND client_id=$2 AND state='active'`, c.environment, op.ClientID, retire); e != nil {
				return e
			}
		}
		result, e := tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='active' WHERE environment=$1 AND client_id=$2 AND version=$3 AND state='staged' AND claimed_at IS NOT NULL AND not_before<=clock_timestamp() AND not_after>clock_timestamp()`, c.environment, op.ClientID, op.KeyVersion)
		if e != nil {
			return e
		}
		if e = oneResult(result); e != nil {
			return e
		}
	case DisableKey:
		if _, e := tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='disabled' WHERE environment=$1 AND client_id=$2 AND version=$3`, c.environment, op.ClientID, op.KeyVersion); e != nil {
			return e
		}
	default:
		return ErrInvalid
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.clients SET revision=revision+1 WHERE environment=$1 AND client_id=$2 AND revision=$3`, c.environment, op.ClientID, op.ExpectedRevision)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	return nil
}
func digestBytesMust(m controlManifest) string {
	raw, e := manifest.Canonical(m)
	if e != nil {
		return ""
	}
	return digestBytes(raw)
}

func deliveryInput(environment, client string, version uint64, issue, fingerprint, signingFingerprint, purpose string, nonce []byte) ([]byte, error) {
	return manifest.Canonical(map[string]any{"environment": environment, "clientId": client, "version": strconv.FormatUint(version, 10), "issueId": issue, "recipientFingerprint": fingerprint, "recipientSigningFingerprint": signingFingerprint, "purpose": purpose, "nonce": base64.RawURLEncoding.EncodeToString(nonce)})
}

type keyDelivery struct {
	signingDER                           []byte
	signingFingerprint                   string
	client                               string
	version                              uint64
	state, root, format, fingerprint     string
	cipher, encrypted, der, claim, proof []byte
	claimed                              bool
	valid                                bool
}

func (c *DevelopmentControl) delivery(ctx context.Context, tx *sql.Tx, issue string) (keyDelivery, error) {
	var k keyDelivery
	e := tx.QueryRowContext(ctx, `SELECT k.client_id,k.version,k.state,k.root_id,k.format,k.recipient_fingerprint,k.ciphertext,k.delivery_ciphertext,k.recipient_der,k.claim_nonce,k.proof_nonce,k.claimed_at IS NOT NULL,
 c.state='enabled' AND p.enabled AND r.enabled AND k.not_before<=clock_timestamp() AND k.not_after>clock_timestamp() AND k.claim_expires>clock_timestamp(),k.recipient_signing_der,k.recipient_signing_fingerprint
 FROM keygate.key_versions k JOIN keygate.clients c ON c.environment=k.environment AND c.client_id=k.client_id
 JOIN keygate.auth_profiles p ON p.environment=c.environment AND p.profile_id=c.profile_id AND p.version=c.profile_version
 JOIN keygate.client_roots r ON r.environment=k.environment AND r.root_id=k.root_id
 WHERE k.environment=$1 AND k.issue_id=$2`, c.environment, issue).Scan(&k.client, &k.version, &k.state, &k.root, &k.format, &k.fingerprint, &k.cipher, &k.encrypted, &k.der, &k.claim, &k.proof, &k.claimed, &k.valid, &k.signingDER, &k.signingFingerprint)
	return k, e
}

// DeliveryChallenge 仅返回非秘密挑战；所有交付适配器仍必须限制请求大小、速率并使用可信 TLS。
// 随机 issueID 不是领取凭据，领取必须证明持有清单固定公钥对应的私钥。
func (c *DevelopmentControl) DeliveryChallenge(ctx context.Context, issue string) ([]byte, error) {
	if !access.ValidID(issue) {
		return nil, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	k, e := c.delivery(ctx, tx, issue)
	if e != nil {
		return nil, ErrDenied
	}
	if !k.valid || k.state != "pending" || k.claimed {
		return nil, ErrDenied
	}
	input, e := deliveryInput(c.environment, k.client, k.version, issue, k.fingerprint, k.signingFingerprint, "keygate-delivery-claim-v1", k.claim)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return input, nil
}

type DeliveryBundle struct{ Ciphertext, OAEPLabel, PossessionInput []byte }

// ClaimDelivery 私钥签名验通过后原子消费一次领取；响应丢失不重发，需停用后新建版本。
func (c *DevelopmentControl) ClaimDelivery(ctx context.Context, issue string, signature []byte, trace string) (DeliveryBundle, error) {
	if !access.ValidID(issue) || !access.ValidID(trace) || len(signature) != ed25519.SignatureSize {
		return DeliveryBundle{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return DeliveryBundle{}, e
	}
	defer tx.Rollback()
	k, e := c.delivery(ctx, tx, issue)
	if e != nil {
		return DeliveryBundle{}, ErrDenied
	}
	if !k.valid || k.state != "pending" || k.claimed {
		return DeliveryBundle{}, ErrDenied
	}
	parsed, e := x509.ParsePKIXPublicKey(k.signingDER)
	if e != nil {
		return DeliveryBundle{}, ErrInvalid
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return DeliveryBundle{}, ErrInvalid
	}
	input, e := deliveryInput(c.environment, k.client, k.version, issue, k.fingerprint, k.signingFingerprint, "keygate-delivery-claim-v1", k.claim)
	if e != nil {
		return DeliveryBundle{}, e
	}
	if !ed25519.Verify(pub, input, signature) {
		return DeliveryBundle{}, ErrDenied
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.key_versions SET claimed_at=clock_timestamp() WHERE environment=$1 AND issue_id=$2 AND claimed_at IS NULL AND state='pending' AND claim_expires>clock_timestamp() AND not_after>clock_timestamp()`, c.environment, issue)
	if e != nil {
		return DeliveryBundle{}, e
	}
	if e = oneResult(result); e != nil {
		return DeliveryBundle{}, e
	}
	if e = c.audit(ctx, tx, trace, "recipient-"+k.fingerprint, "key_claim", issue, "success"); e != nil {
		return DeliveryBundle{}, e
	}
	label, e := deliveryInput(c.environment, k.client, k.version, issue, k.fingerprint, k.signingFingerprint, "keygate-delivery-wrap-v1", nil)
	if e != nil {
		return DeliveryBundle{}, e
	}
	proof, e := deliveryInput(c.environment, k.client, k.version, issue, k.fingerprint, k.signingFingerprint, "keygate-enrollment-v1", k.proof)
	if e != nil {
		return DeliveryBundle{}, e
	}
	if e = tx.Commit(); e != nil {
		return DeliveryBundle{}, e
	}
	c.logger.InfoContext(ctx, "客户端密钥已加密交付", "request_id", trace, "approval_id", issue, "client_id", k.client, "key_version", k.version, "result", "claimed")
	return DeliveryBundle{k.encrypted, label, proof}, nil
}

// ConfirmPossession 要求领取后用客户端秘密验证独立 enrollment challenge，不把交付签名当持有证明。
func (k *DevelopmentKeys) ConfirmPossession(ctx context.Context, issue string, mac []byte, trace string) error {
	if !access.ValidID(issue) || !access.ValidID(trace) || len(mac) != 32 {
		return ErrInvalid
	}
	c := k.control
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	d, e := c.delivery(ctx, tx, issue)
	if e != nil {
		return ErrDenied
	}
	if !d.valid || d.state != "pending" || !d.claimed || d.root != k.rootID {
		return ErrDenied
	}
	if e = k.rootMatches(ctx, tx); e != nil {
		return e
	}
	secret, e := k.wrapper.Open(keycrypto.Binding{Environment: c.environment, ClientID: d.client, KeyID: d.client, Version: d.version, Purpose: "client_auth"}, keycrypto.Envelope{Format: d.format, RootID: d.root, Ciphertext: d.cipher})
	if e != nil {
		return e
	}
	defer clear(secret)
	input, e := deliveryInput(c.environment, d.client, d.version, issue, d.fingerprint, d.signingFingerprint, "keygate-enrollment-v1", d.proof)
	if e != nil {
		return e
	}
	h := hmac.New(sha256.New, secret)
	h.Write(input)
	if !hmac.Equal(h.Sum(nil), mac) {
		return ErrDenied
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.key_versions SET state='staged' WHERE environment=$1 AND issue_id=$2 AND state='pending' AND claimed_at IS NOT NULL AND claim_expires>clock_timestamp() AND not_after>clock_timestamp()`, c.environment, issue)
	if e != nil {
		return e
	}
	if e = oneResult(result); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.clients SET revision=revision+1 WHERE environment=$1 AND client_id=$2`, c.environment, d.client); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, "recipient-"+d.fingerprint, "key_possession", issue, "success"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.InfoContext(ctx, "客户端密钥持有证明已确认", "request_id", trace, "approval_id", issue, "client_id", d.client, "key_version", d.version, "result", "staged")
	return nil
}

type KeyMetadata struct {
	ClientID            string
	Version             uint64
	State               string
	NotBefore, NotAfter time.Time
}

func (c *DevelopmentControl) Key(ctx context.Context, token, client string, version uint64) (KeyMetadata, error) {
	if !access.ValidID(client) || version == 0 || version > 9007199254740991 {
		return KeyMetadata{}, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return KeyMetadata{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return KeyMetadata{}, e
	}
	if !c.has(ctx, tx, a.id, access.Viewer, client) {
		return KeyMetadata{}, ErrDenied
	}
	var k KeyMetadata
	e = tx.QueryRowContext(ctx, `SELECT client_id,version,CASE WHEN not_after<=clock_timestamp() AND state IN ('pending','staged','active','retiring') THEN 'expired' ELSE state END,not_before,not_after FROM keygate.key_versions WHERE environment=$1 AND client_id=$2 AND version=$3`, c.environment, client, version).Scan(&k.ClientID, &k.Version, &k.State, &k.NotBefore, &k.NotAfter)
	if e != nil {
		return k, e
	}
	if e = tx.Commit(); e != nil {
		return KeyMetadata{}, e
	}
	return k, nil
}

// EmergencyDisableClient 只收紧状态并递增修订，任何仍在预计算的签发结果都会在最终 CAS 前被拒绝。
func (c *DevelopmentControl) EmergencyDisableClient(ctx context.Context, token, client, trace string) error {
	if !access.ValidID(client) || !access.ValidID(trace) {
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
	if !c.has(ctx, tx, a.id, access.EmergencyOperator, client) {
		return ErrDenied
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.clients SET state='disabled',revision=revision+1 WHERE environment=$1 AND client_id=$2 AND state='enabled'`, c.environment, client)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if e = c.audit(ctx, tx, trace, a.id, "client_disable", client, "success"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.WarnContext(ctx, "客户端已应急停用", "request_id", trace, "client_id", client, "actor_id", a.id, "result", "disabled")
	return nil
}

// 根标识必须绑定同一份实际材料；进程重启时不能用同一 rootId 悄悄替换软件根。
func (k *DevelopmentKeys) rootMatches(ctx context.Context, tx *sql.Tx) error {
	var yes bool
	e := tx.QueryRowContext(ctx, `SELECT enabled AND key_fingerprint=$3 FROM keygate.client_roots WHERE environment=$1 AND root_id=$2`, k.control.environment, k.rootID, k.fingerprint).Scan(&yes)
	if e != nil {
		return e
	}
	if !yes {
		return ErrDenied
	}
	return nil
}

func oneResult(result sql.Result) error {
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

// 接收方签名与加密使用独立算法和密钥，不把 OAEP 解密密钥同时用作签名密钥。
func recipientSigningKey(encoded, fingerprint string) (ed25519.PublicKey, []byte, error) {
	der, e := base64.RawStdEncoding.DecodeString(encoded)
	if e != nil || len(der) > 128 || base64.RawStdEncoding.EncodeToString(der) != encoded || digestBytes(der) != fingerprint {
		return nil, nil, ErrInvalid
	}
	parsed, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return nil, nil, ErrInvalid
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, nil, ErrInvalid
	}
	return pub, der, nil
}
