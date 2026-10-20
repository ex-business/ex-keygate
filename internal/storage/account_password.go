package storage

import (
	"context"
	"ex-keygate/internal/password"
)

type PasswordSnapshot struct {
	Principal, Username, Hash string
	Revision                  int64
}

// PasswordChangeSnapshot 先消耗跨节点预算，再由HTTP层在事务外计算摘要，避免口令猜测占用安全域锁。
func (c *DevelopmentControl) PasswordChangeSnapshot(ctx context.Context, token string) (PasswordSnapshot, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return PasswordSnapshot{}, e
	}
	defer tx.Rollback()
	a, e := c.actor(ctx, tx, token, true)
	if e != nil {
		return PasswordSnapshot{}, e
	}
	var v PasswordSnapshot
	v.Principal = a.id
	e = tx.QueryRowContext(ctx, `SELECT username,password_hash,revision FROM keygate.local_accounts WHERE environment=$1 AND principal_id=$2 AND enabled AND locked_until<=clock_timestamp()`, c.environment, a.id).Scan(&v.Username, &v.Hash, &v.Revision)
	if e != nil {
		return v, ErrDenied
	}
	var allowed bool
	e = tx.QueryRowContext(ctx, `UPDATE keygate.local_login_budget SET attempts=CASE WHEN started_at<=clock_timestamp()-interval '1 minute' THEN 1 ELSE attempts+1 END,started_at=CASE WHEN started_at<=clock_timestamp()-interval '1 minute' THEN clock_timestamp() ELSE started_at END WHERE environment=$1 AND (attempts<60 OR started_at<=clock_timestamp()-interval '1 minute') RETURNING true`, c.environment).Scan(&allowed)
	if e != nil {
		return v, ErrDenied
	}
	return v, tx.Commit()
}
func (c *DevelopmentControl) ChangeOwnPassword(ctx context.Context, token string, snapshot PasswordSnapshot, matched bool, newHash, trace string) error {
	if _, _, e := password.Parse(newHash); e != nil {
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
	if a.id != snapshot.Principal {
		return ErrDenied
	}
	var encoded string
	var revision int64
	if e = tx.QueryRowContext(ctx, `SELECT password_hash,revision FROM keygate.local_accounts WHERE environment=$1 AND principal_id=$2 AND username=$3 AND enabled AND locked_until<=clock_timestamp()`, c.environment, a.id, snapshot.Username).Scan(&encoded, &revision); e != nil {
		return ErrDenied
	}
	if encoded != snapshot.Hash || revision != snapshot.Revision {
		return ErrConflict
	}
	if !matched {
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.local_accounts SET failures=LEAST(failures+1,5),locked_until=CASE WHEN failures>=4 THEN clock_timestamp()+interval '15 minutes' ELSE locked_until END WHERE environment=$1 AND principal_id=$2`, c.environment, a.id); e != nil {
			return e
		}
		if e = c.audit(ctx, tx, trace, a.id, "account_password_change", a.id, "denied"); e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		return ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.local_accounts SET password_hash=$3,revision=revision+1,failures=0 WHERE environment=$1 AND principal_id=$2`, c.environment, a.id, newHash); e != nil {
		return e
	}
	if e = c.invalidateAccountSessions(ctx, tx, a.id); e != nil {
		return e
	}
	if e = c.audit(ctx, tx, trace, a.id, "account_password_change", a.id, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
func (c *DevelopmentControl) OwnAccount(ctx context.Context, token string) (*AccountInfo, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	a, e := c.identityActor(ctx, tx, token, false)
	if e != nil {
		return nil, e
	}
	out, e := c.accountInfo(ctx, tx, a.id)
	if e != nil {
		return nil, e
	}
	return out, tx.Commit()
}
