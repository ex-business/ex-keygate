package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"ex-keygate/internal/access"
)

// AuditSink 是独立归档边界：重复 eventId 必须比对完全相同的字节，冲突不能覆盖原归档。
// 接口返回前必须持久化成功；未来可接不可变对象存储，不把数据库摘要自称外部可信锚。
type AuditSink interface {
	Put(context.Context, string, []byte) (string, error)
}

// ArchiveAuditBatch 仅供受控运维身份调用，不挂管理 HTTP。先归档后确认，崩溃重试由事件唯一键去重。
func (s *Store) ArchiveAuditBatch(ctx context.Context, environment string, sink AuditSink, limit int) (int, error) {
	if !access.ValidID(environment) || sink == nil || limit < 1 || limit > 1000 {
		return 0, ErrInvalid
	}
	rows, e := s.db.QueryContext(ctx, `SELECT a.sequence,a.event_id,s.environment,s.client_id,a.request_id,a.actor_id,a.action,a.target_id,a.result,a.created_at FROM keygate.audit_outbox o JOIN keygate.scoped_audit s ON s.event_id=o.event_id JOIN keygate.audit_events a ON a.event_id=o.event_id WHERE s.environment=$1 AND o.archived_at IS NULL ORDER BY a.sequence LIMIT $2`, environment, limit)
	if e != nil {
		return 0, e
	}
	events := []AuditEvent{}
	for rows.Next() {
		var a AuditEvent
		if e = rows.Scan(&a.Sequence, &a.EventID, &a.Environment, &a.ClientID, &a.RequestID, &a.ActorID, &a.Action, &a.TargetID, &a.Result, &a.RecordedAt); e != nil {
			rows.Close()
			return 0, e
		}
		events = append(events, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	done := 0
	for _, a := range events {
		raw, e := json.Marshal(a)
		if e != nil {
			return done, e
		}
		hash, e := sink.Put(ctx, a.EventID, raw)
		if e != nil {
			return done, e
		}
		if hash != digestBytes(raw) {
			return done, ErrConflict
		}
		// 外部写成功后再次比较权威事件，防止归档期间变化被错误确认。
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return done, e
		}
		current, e := auditEventByID(ctx, tx, a.EventID)
		if e != nil {
			tx.Rollback()
			return done, e
		}
		actual, e := json.Marshal(current)
		if e != nil || string(actual) != string(raw) {
			tx.Rollback()
			return done, ErrConflict
		}
		result, e := tx.ExecContext(ctx, `UPDATE keygate.audit_outbox SET archived_hash=$2,archived_at=COALESCE(archived_at,clock_timestamp()) WHERE event_id=$1 AND (archived_hash IS NULL OR archived_hash=$2)`, a.EventID, hash)
		if e != nil {
			tx.Rollback()
			return done, e
		}
		if e = oneResult(result); e != nil {
			tx.Rollback()
			return done, e
		}
		if e = tx.Commit(); e != nil {
			return done, e
		}
		done++
	}
	return done, nil
}

func auditEventByID(ctx context.Context, tx interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (AuditEvent, error) {
	var a AuditEvent
	e := tx.QueryRowContext(ctx, `SELECT a.sequence,a.event_id,s.environment,s.client_id,a.request_id,a.actor_id,a.action,a.target_id,a.result,a.created_at FROM keygate.audit_events a JOIN keygate.scoped_audit s ON s.event_id=a.event_id WHERE a.event_id=$1`, id).Scan(&a.Sequence, &a.EventID, &a.Environment, &a.ClientID, &a.RequestID, &a.ActorID, &a.Action, &a.TargetID, &a.Result, &a.RecordedAt)
	return a, e
}

// CompareArchivedAudit 对外部已验签的每个事件检查数据库，检测已归档事实被删改或备份回退。
func (s *Store) CompareArchivedAudit(ctx context.Context, environment string, raw []byte) error {
	var expected AuditEvent
	if json.Unmarshal(raw, &expected) != nil || expected.Environment != environment {
		return ErrInvalid
	}
	current, e := auditEventByID(ctx, s.db, expected.EventID)
	if e != nil {
		return e
	}
	actual, e := json.Marshal(current)
	if e != nil {
		return e
	}
	if string(actual) != string(raw) {
		return ErrConflict
	}
	return nil
}

type ArchiveStatus struct {
	Count, Pending int64
	HighWater      int64
}

func (s *Store) AuditArchiveStatus(ctx context.Context, environment string) (ArchiveStatus, error) {
	var out ArchiveStatus
	if !access.ValidID(environment) {
		return out, ErrInvalid
	}
	e := s.db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE o.archived_at IS NULL),COALESCE(max(a.sequence),0) FROM keygate.scoped_audit s JOIN keygate.audit_outbox o ON o.event_id=s.event_id JOIN keygate.audit_events a ON a.event_id=s.event_id WHERE s.environment=$1`, environment).Scan(&out.Count, &out.Pending, &out.HighWater)
	return out, e
}
