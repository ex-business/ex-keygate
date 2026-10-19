// Package approval defines immutable approval transitions, not a persistent authorization service.
// Callers must commit transitions with compare-and-swap in the same durable transaction as audit.
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	ErrInvalid   = errors.New("invalid approval request")
	ErrExpired   = errors.New("approval expired")
	ErrState     = errors.New("invalid approval state")
	ErrForbidden = errors.New("approval forbidden")
	ErrDuplicate = errors.New("duplicate vote")
	ErrConflict  = errors.New("target version conflict")
)

type State string

const (
	Pending   State = "pending"
	Approved  State = "approved"
	Rejected  State = "rejected"
	Cancelled State = "cancelled"
)

type Execution string

const (
	NotStarted Execution = "not_started"
	Executing  Execution = "executing"
	Succeeded  Execution = "succeeded"
	Failed     Execution = "failed"
	Unknown    Execution = "unknown"
)

type Operation struct {
	Kind          string `json:"kind"`
	Target        string `json:"target"`
	TargetVersion uint64 `json:"targetVersion"`
	// Parameters must contain references and non-secret settings, never key material.
	Parameters json.RawMessage `json:"parameters"`
}

type Policy struct {
	ID        string
	Version   uint64
	Approvers []string
	Threshold int
}

type Vote struct {
	Actor  string
	At     time.Time
	Accept bool
}

type Request struct {
	id        string
	applicant string
	operation Operation
	policy    Policy
	digest    string
	created   time.Time
	expires   time.Time
	state     State
	execution Execution
	votes     []Vote
	revision  uint64
}

// New snapshots the operation and policy. Later policy revocation must still be
// checked against authoritative state before execution; this snapshot is not a grant.
func New(id, applicant string, op Operation, policy Policy, now, expires time.Time) (Request, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(applicant) == "" || strings.TrimSpace(op.Kind) == "" || strings.TrimSpace(op.Target) == "" || !json.Valid(op.Parameters) || len(op.Parameters) > 65536 || policy.ID == "" || policy.Version == 0 || now.IsZero() || !expires.After(now) {
		return Request{}, ErrInvalid
	}
	seen := make(map[string]bool)
	for _, actor := range policy.Approvers {
		if strings.TrimSpace(actor) == "" || actor == applicant || seen[actor] {
			return Request{}, ErrInvalid
		}
		seen[actor] = true
	}
	if policy.Threshold < 2 || policy.Threshold > len(seen) {
		return Request{}, ErrInvalid
	}
	op.Parameters = slices.Clone(op.Parameters)
	policy.Approvers = slices.Clone(policy.Approvers)
	// The digest includes the request identity, policy snapshot and expiry, preventing
	// approvals for one request from being treated as authorization for another.
	payload, err := json.Marshal(struct {
		ID, Applicant    string
		Operation        Operation
		Policy           Policy
		Created, Expires time.Time
	}{id, applicant, op, policy, now.UTC(), expires.UTC()})
	if err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	sum := sha256.Sum256(payload)
	return Request{id: id, applicant: applicant, operation: op, policy: policy, digest: hex.EncodeToString(sum[:]), created: now, expires: expires, state: Pending, execution: NotStarted, revision: 1}, nil
}

func (r Request) Execution() Execution { return r.execution }

func (r Request) ID() string       { return r.id }
func (r Request) Digest() string   { return r.digest }
func (r Request) State() State     { return r.state }
func (r Request) Revision() uint64 { return r.revision }
func (r Request) Operation() Operation {
	op := r.operation
	op.Parameters = slices.Clone(op.Parameters)
	return op
}
func (r Request) Votes() []Vote { return slices.Clone(r.votes) }

func (r Request) validAt(now time.Time) error {
	if r.id == "" || now.Before(r.created) {
		return ErrInvalid
	}
	if !now.Before(r.expires) {
		return ErrExpired
	}
	return nil
}

// Vote returns a new snapshot. The old revision must be checked on persistence;
// concurrent snapshots cannot be merged or counted as independent approvals.
func (r Request) Vote(actor string, accept bool, now time.Time) (Request, error) {
	if err := r.validAt(now); err != nil {
		return Request{}, err
	}
	if r.state != Pending {
		return Request{}, ErrState
	}
	if actor == r.applicant || !slices.Contains(r.policy.Approvers, actor) {
		return Request{}, ErrForbidden
	}
	if len(r.votes) > 0 && now.Before(r.votes[len(r.votes)-1].At) {
		return Request{}, ErrInvalid
	}
	for _, v := range r.votes {
		if v.Actor == actor {
			return Request{}, ErrDuplicate
		}
	}
	r.votes = append(slices.Clone(r.votes), Vote{actor, now, accept})
	r.revision++
	if !accept {
		r.state = Rejected
	} else if len(r.votes) >= r.policy.Threshold {
		r.state = Approved
	}
	return r, nil
}

func (r Request) Cancel(actor string, now time.Time) (Request, error) {
	if err := r.validAt(now); err != nil {
		return Request{}, err
	}
	if actor != r.applicant {
		return Request{}, ErrForbidden
	}
	if (r.state != Pending && r.state != Approved) || r.execution != NotStarted {
		return Request{}, ErrState
	}
	r.state = Cancelled
	r.revision++
	return r, nil
}

// Begin requires a fresh target version and current policy version. The service
// must also recheck actor eligibility and persist the transition atomically before
// any side effect. This domain method does not perform authorization or locking.
func (r Request) Begin(targetVersion, policyVersion uint64, now time.Time) (Request, error) {
	if err := r.validAt(now); err != nil {
		return Request{}, err
	}
	if r.state != Approved || r.execution != NotStarted {
		return Request{}, ErrState
	}
	if targetVersion != r.operation.TargetVersion || policyVersion != r.policy.Version {
		return Request{}, ErrConflict
	}
	r.execution = Executing
	r.revision++
	return r, nil
}

// Unknown outcomes cannot be retried by restarting this request: reconciliation
// must determine the external result before a separately authorized recovery.
func (r Request) Finish(result Execution) (Request, error) {
	if r.execution != Executing {
		return Request{}, ErrState
	}
	if result != Succeeded && result != Failed && result != Unknown {
		return Request{}, ErrInvalid
	}
	r.execution = result
	r.revision++
	return r, nil
}
