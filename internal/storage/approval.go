package storage

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"ex-keygate/internal/approval"
)

var ErrApprovalNotFound = errors.New("approval request not found")

// CreateApproval 将不可变新草案与审计同事务持久化；调用方必须核验申请人及权威策略，节点切换不替代业务授权。
func (s *Store) CreateApproval(ctx context.Context, r approval.Request, a Audit) error {
	d := r.Draft()
	if !identifier.MatchString(d.ID) || r.State() != approval.Pending || r.Revision() != 1 || r.Execution() != approval.NotStarted || !a.valid() || a.ActorID != d.Applicant || a.TargetID != d.ID || a.Action != "approval_create" || a.Result != "pending" {
		return ErrInvalid
	}
	// Reconstruction rejects a zero or otherwise invalid domain object.
	if _, err := approval.RestoreVotes(d, nil); err != nil {
		return err
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > 1<<20 {
		return ErrInvalid
	}
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var now time.Time
	if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return err
	}
	if now.Before(d.Created) || !now.Before(d.Expires) {
		return approval.ErrExpired
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO keygate.approval_requests(id,draft,votes,revision) VALUES($1,$2,$3,1)", d.ID, raw, []byte("[]")); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}

type rowScanner interface{ Scan(...any) error }

func restoreApproval(row rowScanner) (approval.Request, error) {
	var raw, votesRaw []byte
	var revision uint64
	if err := row.Scan(&raw, &votesRaw, &revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return approval.Request{}, ErrApprovalNotFound
		}
		return approval.Request{}, err
	}
	if len(raw) > 1<<20 || len(votesRaw) > 1<<20 {
		return approval.Request{}, ErrInvalid
	}
	var draft approval.Draft
	var votes []approval.Vote
	if err := json.Unmarshal(raw, &draft); err != nil {
		return approval.Request{}, ErrInvalid
	}
	if err := json.Unmarshal(votesRaw, &votes); err != nil {
		return approval.Request{}, ErrInvalid
	}
	r, err := approval.RestoreVotes(draft, votes)
	if err != nil {
		return approval.Request{}, err
	}
	if r.Revision() != revision {
		return approval.Request{}, ErrInvalid
	}
	return r, nil
}
func (s *Store) Approval(ctx context.Context, id string) (approval.Request, error) {
	if !identifier.MatchString(id) {
		return approval.Request{}, ErrInvalid
	}
	tx, e := s.beginRuntime(ctx)
	if e != nil {
		return approval.Request{}, e
	}
	defer tx.Rollback()
	out, e := restoreApproval(tx.QueryRowContext(ctx, "SELECT draft,votes,revision FROM keygate.approval_requests WHERE id=$1", id))
	if e != nil {
		return approval.Request{}, e
	}
	if e = tx.Commit(); e != nil {
		return approval.Request{}, e
	}
	return out, nil
}

// CastVote 要求审批人审阅的摘要，并通过共享行锁串行跨节点投票；审计失败回滚。
// 调用方仍须验证人员和当前资格，客户端自报 actor 不能成为受信身份。
func (s *Store) CastVote(ctx context.Context, id, digest, actor string, accept bool, a Audit) (approval.Request, error) {
	result := "rejected"
	if accept {
		result = "accepted"
	}
	if !identifier.MatchString(id) || !identifier.MatchString(actor) || !a.valid() || a.ActorID != actor || a.TargetID != id || a.Action != "approval_vote" || a.Result != result {
		return approval.Request{}, ErrInvalid
	}
	tx, err := s.beginRuntime(ctx)
	if err != nil {
		return approval.Request{}, err
	}
	defer tx.Rollback()
	r, err := restoreApproval(tx.QueryRowContext(ctx, "SELECT draft,votes,revision FROM keygate.approval_requests WHERE id=$1 FOR UPDATE", id))
	if err != nil {
		return approval.Request{}, err
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(r.Digest())) != 1 {
		return approval.Request{}, approval.ErrConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return approval.Request{}, err
	}
	next, err := r.Vote(actor, accept, now)
	if err != nil {
		return approval.Request{}, err
	}
	votesRaw, err := json.Marshal(next.Votes())
	if err != nil || len(votesRaw) > 1<<20 {
		return approval.Request{}, ErrInvalid
	}
	if _, err = tx.ExecContext(ctx, "UPDATE keygate.approval_requests SET votes=$1,revision=$2 WHERE id=$3", votesRaw, next.Revision(), id); err != nil {
		return approval.Request{}, err
	}
	if err = appendAudit(ctx, tx, a); err != nil {
		return approval.Request{}, err
	}
	if err = tx.Commit(); err != nil {
		return approval.Request{}, err
	}
	return next, nil
}
