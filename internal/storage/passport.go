package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	"ex-keygate/internal/access"
	"ex-keygate/internal/passport"
)

const PassportIntrospection = "passport_introspection"

type PassportOperation struct {
	OperationID          string   `json:"operationId"`
	EndpointBinding      string   `json:"endpointBinding"`
	Operation            string   `json:"operation"`
	Audiences            []string `json:"audiences,omitempty"`
	RecipientPublicKey   string   `json:"recipientPublicKey,omitempty"`
	RecipientFingerprint string   `json:"recipientFingerprint,omitempty"`
}

// ConfigurePassport is a trusted startup hook, never a browser-facing grant.
func (c *DevelopmentControl) ConfigurePassport(p *passport.Client) error {
	if p == nil || c.passport != nil {
		return ErrInvalid
	}
	c.passport = p
	return nil
}
func (c *DevelopmentControl) validatePassportOperation(op ControlOperation) error {
	if c.passport == nil || op.Passport == nil || op.Passport.EndpointBinding != c.passport.EndpointBinding() || !validDigest(op.Passport.OperationID) || !access.ValidID(op.ClientID) {
		return ErrInvalid
	}
	copy := op
	copy.Passport = nil
	copy.Kind = ""
	copy.ClientID = ""
	copy.ExpectedRevision = 0
	if !reflect.DeepEqual(copy, ControlOperation{}) {
		return ErrInvalid
	}
	b := passportRequest(op.Passport.OperationID, op)
	if b.Validate() != nil {
		return ErrInvalid
	}
	p := op.Passport
	if p.Operation == "disable" {
		if p.RecipientPublicKey != "" || p.RecipientFingerprint != "" {
			return ErrInvalid
		}
	} else if _, _, e := recipientKey(p.RecipientPublicKey, p.RecipientFingerprint); e != nil {
		return e
	}
	return nil
}
func passportRequest(operationID string, op ControlOperation) passport.Request {
	return passport.Request{OperationID: operationID, Operation: op.Passport.Operation, ClientID: op.ClientID, Audiences: op.Passport.Audiences, ExpectedRevision: int64(op.ExpectedRevision)}
}

// Reservation is durable before contacting Passport. All later attempts query
// this operation first; never infer remote success from a client's revision.
func (c *DevelopmentControl) reservePassport(ctx context.Context, token, id, digest, trace string) (passport.Request, error) {
	var b passport.Request
	if c.passport == nil || !access.ValidID(id) || !access.ValidID(trace) {
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
	if subtle.ConstantTimeCompare([]byte(digest), []byte(r.Digest)) != 1 || m.Operation.Kind != PassportIntrospection || m.Operation.Passport == nil {
		return b, ErrConflict
	}
	var operationID, binding, hash, storedDigest string
	e = tx.QueryRowContext(ctx, `SELECT operation_id,endpoint_binding,request_hash,digest FROM keygate.passport_executions WHERE environment=$1 AND request_id=$2`, c.environment, id).Scan(&operationID, &binding, &hash, &storedDigest)
	if e == nil {
		b = passportRequest(operationID, m.Operation)
		if binding != c.passport.EndpointBinding() || binding != m.Operation.Passport.EndpointBinding || operationID != m.Operation.Passport.OperationID || hash != b.Hash() || storedDigest != digest {
			return passport.Request{}, ErrConflict
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
	if e = c.validatePassportOperation(m.Operation); e != nil {
		return b, e
	}
	operationID = m.Operation.Passport.OperationID
	b = passportRequest(operationID, m.Operation)
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.passport_executions(environment,request_id,operation_id,digest,endpoint_binding,request_hash) VALUES($1,$2,$3,$4,$5,$6)`, c.environment, id, operationID, digest, c.passport.EndpointBinding(), b.Hash()); e != nil {
		return b, e
	}
	// Existing withdrawal logic treats this reservation as execution already begun.
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.control_executions(environment,request_id,execution_id,digest,state) VALUES($1,$2,$3,$4,'unknown')`, c.environment, id, operationID, digest); e != nil {
		return b, e
	}
	if e = c.audit(ctx, tx, trace, "executor-service", "passport_reserved", id, "unknown"); e != nil {
		return b, e
	}
	return b, tx.Commit()
}
func (c *DevelopmentControl) executePassport(ctx context.Context, token, id, digest, trace string) error {
	b, e := c.reservePassport(ctx, token, id, digest, trace)
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
	if state == "failed" {
		return passport.ErrRejected
	}
	result, e := c.passport.Query(ctx, b)
	if errors.Is(e, passport.ErrNotFound) {
		// No new remote side effects after expiry, policy change or revocation. Query
		// reconciliation remains possible for an operation already committed remotely.
		if r.Decision != "approved" {
			return ErrDenied
		}
		if e = c.liveManifest(ctx, tx, m); e != nil {
			return e
		}
		if e = c.verifyVotes(ctx, tx, m); e != nil {
			return e
		}
		result, e = c.passport.Execute(ctx, b)
	}
	if e != nil {
		return e
	}
	delivery := "not_required"
	var ciphertext, label []byte
	if b.Operation != "disable" {
		delivery = "unavailable"
		if result.ClientSecret != "" {
			pub, _, err := recipientKey(m.Operation.Passport.RecipientPublicKey, m.Operation.Passport.RecipientFingerprint)
			if err != nil {
				return err
			}
			label, _ = json.Marshal(struct{ ApprovalID, Digest, OperationID, RequestHash string }{id, digest, b.OperationID, b.Hash()})
			secret := []byte(result.ClientSecret)
			ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, secret, label)
			clear(secret)
			result.ClientSecret = ""
			if err != nil {
				return ErrInvalid
			}
			delivery = "encrypted"
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.passport_executions SET state='succeeded',revision=$3,delivery_state=$4,ciphertext=$5,oaep_label=$6 WHERE environment=$1 AND request_id=$2`, c.environment, id, result.Revision, delivery, ciphertext, label); e != nil {
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
	if e = c.audit(ctx, tx, trace, "executor-service", "passport_execute", id, "success"); e != nil {
		return e
	}
	return tx.Commit()
}

type PassportOutcome struct {
	OperationID       string        `json:"operationId"`
	State             string        `json:"state"`
	Revision          sql.NullInt64 `json:"-"`
	CommittedRevision *int64        `json:"revision,omitempty"`
	DeliveryState     string        `json:"deliveryState"`
	Ciphertext        []byte        `json:"ciphertext,omitempty"`
	OAEPLabel         []byte        `json:"oaepLabel,omitempty"`
}

func (c *DevelopmentControl) PassportOutcome(ctx context.Context, token, id string) (PassportOutcome, error) {
	var out PassportOutcome
	if !access.ValidID(id) || token == "" {
		return out, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	_, m, e := c.loadRequest(ctx, tx, id)
	if e != nil {
		return out, e
	}
	if e = c.executionActor(ctx, tx, token, m); e != nil {
		return out, e
	}
	e = tx.QueryRowContext(ctx, `SELECT operation_id,state,revision,delivery_state,ciphertext,oaep_label FROM keygate.passport_executions WHERE environment=$1 AND request_id=$2`, c.environment, id).Scan(&out.OperationID, &out.State, &out.Revision, &out.DeliveryState, &out.Ciphertext, &out.OAEPLabel)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrConflict
	}
	if e != nil {
		return out, e
	}
	if out.Revision.Valid {
		out.CommittedRevision = &out.Revision.Int64
	}
	return out, tx.Commit()
}
