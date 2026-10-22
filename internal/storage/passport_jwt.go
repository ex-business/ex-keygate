package storage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"

	"ex-keygate/internal/access"
	"ex-keygate/internal/passport"
)

const PassportJWTKind = "passport_jwt"
const PassportJWTScope = "passport-jwt-management"

type PassportJWT struct {
	OperationID          string `json:"operationId"`
	EndpointBinding      string `json:"endpointBinding"`
	Operation            string `json:"operation"`
	Kid                  string `json:"kid"`
	PublicKey            string `json:"publicKey,omitempty"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint,omitempty"`
	Reason               string `json:"reason"`
}

func (c *DevelopmentControl) ConfigurePassportJWT(p *passport.Client) error {
	if p == nil || c.passportJWT != nil {
		return ErrInvalid
	}
	c.passportJWT = p
	return nil
}
func (c *DevelopmentControl) bindPassportJWT(op ControlOperation, actor, idempotency string) (ControlOperation, error) {
	if c.passportJWT == nil || op.JWT == nil {
		return op, ErrInvalid
	}
	copy := *op.JWT
	op.JWT = &copy
	operationID := digestBytes([]byte(c.environment + "\x00" + actor + "\x00" + idempotency))
	if (copy.OperationID != "" && copy.OperationID != operationID) || (copy.EndpointBinding != "" && copy.EndpointBinding != c.passportJWT.EndpointBinding()) {
		return op, ErrConflict
	}
	op.JWT.OperationID = operationID
	op.JWT.EndpointBinding = c.passportJWT.EndpointBinding()
	if op.JWT.Operation == "publish" {
		public, e := base64.RawURLEncoding.Strict().DecodeString(op.JWT.PublicKey)
		if e != nil || len(public) != 32 {
			return op, ErrInvalid
		}
		hash := sha256.Sum256(public)
		fp := hex.EncodeToString(hash[:])
		if copy.PublicKeyFingerprint != "" && copy.PublicKeyFingerprint != fp {
			return op, ErrConflict
		}
		op.JWT.PublicKeyFingerprint = fp
	}
	return op, nil
}
func (c *DevelopmentControl) validatePassportJWT(op ControlOperation) error {
	if c.passportJWT == nil || op.JWT == nil || op.ClientID != PassportJWTScope || op.JWT.EndpointBinding != c.passportJWT.EndpointBinding() || !validDigest(op.JWT.OperationID) {
		return ErrInvalid
	}
	copy := op
	copy.JWT = nil
	copy.Kind = ""
	copy.ClientID = ""
	copy.ExpectedRevision = 0
	if !reflect.DeepEqual(copy, ControlOperation{}) {
		return ErrInvalid
	}
	b := jwtRequest(op, op.JWT.OperationID, op.JWT.OperationID)
	if b.Validate() != nil {
		return ErrInvalid
	}
	if op.JWT.Operation == "publish" {
		public, _ := base64.RawURLEncoding.Strict().DecodeString(op.JWT.PublicKey)
		hash := sha256.Sum256(public)
		if op.JWT.PublicKeyFingerprint != hex.EncodeToString(hash[:]) {
			return ErrInvalid
		}
	} else if op.JWT.PublicKeyFingerprint != "" {
		return ErrInvalid
	}
	return nil
}
func jwtRequest(op ControlOperation, operationID, digest string) passport.JWTRequest {
	return passport.JWTRequest{OperationID: operationID, ApprovalDigest: digest, Operation: op.JWT.Operation, Kid: op.JWT.Kid, ExpectedRevision: int64(op.ExpectedRevision), PublicKey: op.JWT.PublicKey, Reason: op.JWT.Reason}
}
func (c *DevelopmentControl) reservePassportJWT(ctx context.Context, token, id, digest, trace string) (passport.JWTRequest, error) {
	var b passport.JWTRequest
	if c.passportJWT == nil || !validDigest(digest) || !identifier.MatchString(id) || !identifier.MatchString(trace) {
		return b, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return b, e
	}
	defer tx.Rollback()
	r, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return b, e
	}
	if token != "" {
		if e = c.executionActor(ctx, tx, token, m); e != nil {
			return b, e
		}
	}
	if subtle.ConstantTimeCompare([]byte(r.Digest), []byte(digest)) != 1 || m.Operation.Kind != PassportJWTKind || m.Operation.JWT == nil {
		return b, ErrConflict
	}
	var operationID, binding, hash, storedDigest string
	e = tx.QueryRowContext(ctx, `SELECT operation_id,endpoint_binding,request_hash,digest FROM keygate.passport_executions WHERE environment=$1 AND request_id=$2`, c.environment, id).Scan(&operationID, &binding, &hash, &storedDigest)
	if e == nil {
		b = jwtRequest(m.Operation, operationID, digest)
		if operationID != m.Operation.JWT.OperationID || binding != c.passportJWT.EndpointBinding() || binding != m.Operation.JWT.EndpointBinding || hash != b.Hash() || storedDigest != digest {
			return passport.JWTRequest{}, ErrConflict
		}
		return b, tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return b, e
	}
	if r.Executed || r.Decision != "approved" {
		return b, ErrDenied
	}
	if e = c.liveManifest(ctx, tx, m); e != nil {
		return b, e
	}
	if e = c.verifyVotes(ctx, tx, m); e != nil {
		return b, e
	}
	if e = c.validatePassportJWT(m.Operation); e != nil {
		return b, e
	}
	b = jwtRequest(m.Operation, m.Operation.JWT.OperationID, digest)
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.passport_executions(environment,request_id,operation_id,digest,endpoint_binding,request_hash,delivery_state) VALUES($1,$2,$3,$4,$5,$6,'not_required')`, c.environment, id, b.OperationID, digest, c.passportJWT.EndpointBinding(), b.Hash()); e != nil {
		return b, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.control_executions(environment,request_id,execution_id,digest,state) VALUES($1,$2,$3,$4,'unknown')`, c.environment, id, b.OperationID, digest); e != nil {
		return b, e
	}
	if e = c.audit(ctx, tx, trace, "executor-service", "passport_jwt_reserved", id, "unknown"); e != nil {
		return b, e
	}
	return b, tx.Commit()
}
func (c *DevelopmentControl) executePassportJWT(ctx context.Context, token, id, digest, trace string) error {
	b, e := c.reservePassportJWT(ctx, token, id, digest, trace)
	if e != nil {
		return e
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
	var state string
	if e = tx.QueryRowContext(ctx, `SELECT state FROM keygate.passport_executions WHERE environment=$1 AND request_id=$2 FOR UPDATE`, c.environment, id).Scan(&state); e != nil {
		return e
	}
	if state == "succeeded" {
		return tx.Commit()
	}
	if state != "unknown" {
		return passport.ErrRejected
	}
	result, e := c.passportJWT.QueryJWT(ctx, b)
	if errors.Is(e, passport.ErrNotFound) {
		if r.Decision != "approved" {
			return ErrDenied
		}
		if e = c.liveManifest(ctx, tx, m); e != nil {
			return e
		}
		if e = c.verifyVotes(ctx, tx, m); e != nil {
			return e
		}
		if e = c.validatePassportJWT(m.Operation); e != nil {
			return e
		}
		result, e = c.passportJWT.ExecuteJWT(ctx, b)
	}
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.passport_executions SET state='succeeded',revision=$3,delivery_state='not_required' WHERE environment=$1 AND request_id=$2`, c.environment, id, result.Revision); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_executions SET state='succeeded' WHERE environment=$1 AND request_id=$2`, c.environment, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.control_requests SET executed=true WHERE environment=$1 AND request_id=$2`, c.environment, id); e != nil {
		return e
	}
	if e = c.syncApprovalNotifications(ctx, tx, id); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, "executor-service", "passport_jwt_execute", id, "success"); e != nil {
		return e
	}
	return tx.Commit()
}

func (c *DevelopmentControl) PassportJWTState(ctx context.Context, token string) (passport.JWTState, error) {
	var out passport.JWTState
	if c.passportJWT == nil {
		return out, ErrDenied
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, false)
	if e != nil {
		return out, e
	}
	for _, role := range []access.Role{access.PolicyAdmin, access.Viewer} {
		m, e := c.eligible(ctx, tx, a.id, role, "")
		if e != nil {
			return out, e
		}
		if m.GrantScope != "" {
			return out, ErrDenied
		}
	}
	return c.passportJWT.GetJWTState(ctx)
}
