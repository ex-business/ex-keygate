package storage

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"ex-keygate/internal/httpsign"
	"ex-keygate/internal/keycrypto"
)

// AuthenticateProbe 只认证直接发送给 ExKeyGate 的实际请求，不给外部业务颁发可转移授权。
// 与停用共用域锁；最终状态校验、验签、防重放和提交在同一权威事务，数据库失败不放行。
func (k *DevelopmentKeys) AuthenticateProbe(ctx context.Context, r *http.Request, body []byte, audience string) error {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 {
		return ErrDenied
	}
	m, e := httpsign.Parse(r, body)
	if e != nil {
		return ErrDenied
	}
	c := k.control
	if m.Environment != c.environment || m.Audience != audience {
		return ErrDenied
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var format string
	var cipher []byte
	e = tx.QueryRowContext(ctx, `SELECT k.format,k.ciphertext FROM keygate.key_versions k
 JOIN keygate.clients c ON c.environment=k.environment AND c.client_id=k.client_id
 JOIN keygate.auth_profiles p ON p.environment=c.environment AND p.profile_id=c.profile_id AND p.version=c.profile_version
 JOIN keygate.client_roots r ON r.environment=k.environment AND r.root_id=k.root_id
 WHERE k.environment=$1 AND k.client_id=$2 AND k.version=$3 AND k.root_id=$4
 AND k.state IN ('active','retiring') AND k.claimed_at IS NOT NULL AND k.not_before<=clock_timestamp() AND k.not_after>clock_timestamp()
 AND c.state='enabled' AND p.enabled AND p.client_type='backend' AND p.method='hmac_sha256' AND p.storage='server_vault' AND p.provider_id='internal-software' AND r.enabled AND r.purpose='client_auth'
 AND to_timestamp($5)<=clock_timestamp()+interval '30 seconds' AND to_timestamp($6)>clock_timestamp()`, c.environment, m.ClientID, m.Version, k.rootID, m.Created, m.Expires).Scan(&format, &cipher)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	}
	if e != nil {
		return e
	}
	if e = k.rootMatches(ctx, tx); e != nil {
		return e
	}
	secret, e := k.wrapper.Open(keycrypto.Binding{Environment: c.environment, ClientID: m.ClientID, KeyID: m.ClientID, Version: m.Version, Purpose: "client_auth"}, keycrypto.Envelope{Format: format, RootID: k.rootID, Ciphertext: cipher})
	if e != nil {
		return ErrDenied
	}
	defer clear(secret)
	if !m.Verify(secret) {
		return ErrDenied
	}
	scope, _ := json.Marshal(Scope{Environment: c.environment, ClientID: m.ClientID, KeyID: m.ClientID, Version: m.Version})
	sh := sha256.Sum256(scope)
	nh := sha256.Sum256(m.Nonce[:])
	// 消费时再检查时间边界，保留 nonce 到签名完整失效；提交错误必须按失败处理。
	result, e := tx.ExecContext(ctx, `INSERT INTO keygate.replay_nonces(scope_hash,nonce_hash,expires_at)
 SELECT $1,$2,to_timestamp($3) WHERE to_timestamp($3)>clock_timestamp() AND to_timestamp($4)<=clock_timestamp()+interval '30 seconds'
 AND EXISTS(SELECT 1 FROM keygate.key_versions WHERE environment=$5 AND client_id=$6 AND version=$7 AND state IN ('active','retiring') AND not_after>clock_timestamp()) ON CONFLICT DO NOTHING`, sh[:], nh[:], m.Expires, m.Created, c.environment, m.ClientID, m.Version)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrDenied
	}
	return tx.Commit()
}
