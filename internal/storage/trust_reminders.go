package storage

import (
	"context"
	"database/sql"
	"ex-keygate/internal/access"
	"ex-keygate/trustchain"
	"time"
)

type TrustReminder struct {
	ID              string    `json:"id"`
	RootFingerprint string    `json:"rootFingerprint"`
	ServiceID       string    `json:"serviceId"`
	Kind            string    `json:"kind"`
	Fingerprint     string    `json:"fingerprint"`
	ExpiresAt       time.Time `json:"expiresAt"`
	Severity        string    `json:"severity"`
	State           string    `json:"state"`
	Attempts        int       `json:"attempts"`
}

// TrustReminderPlugin 必须将ID作为幂等键；插件自行维护受控收件人，不接收页面提供的任意目的地址。
type TrustReminderPlugin interface {
	SendTrustReminder(context.Context, TrustReminder) error
}

func reminderSeverity(expiry, now time.Time) string {
	remaining := expiry.Sub(now)
	switch {
	case remaining <= 0:
		return "expired"
	case remaining <= time.Hour:
		return "due_1h"
	case remaining <= 24*time.Hour:
		return "due_24h"
	case remaining <= 7*24*time.Hour:
		return "due_7d"
	}
	return ""
}

// CollectTrustReminders 为后台可信任务扫描当前公开证书，不读取私钥；重复扫描和多节点由唯一约束去重。
func (c *DevelopmentControl) CollectTrustReminders(ctx context.Context) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now, e := controlNow(ctx, tx)
	if e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, `SELECT fingerprint,'' AS service_id,'root' AS kind,certificate,fingerprint FROM keygate.application_trust_roots WHERE environment=$1 UNION ALL SELECT root_fingerprint,'trust-status','status',certificate,fingerprint FROM keygate.application_trust_status_signers WHERE environment=$1 UNION ALL SELECT s.root_fingerprint,s.service_id,'service',c.certificate,c.fingerprint FROM keygate.application_trust_services s JOIN keygate.application_trust_certificates c ON c.environment=s.environment AND c.service_id=s.service_id AND c.version=s.active_version WHERE s.environment=$1 AND NOT s.disabled AND c.state='active'`, c.environment)
	if e != nil {
		return e
	}
	type item struct {
		root, service, kind, fp string
		cert                    []byte
	}
	items := []item{}
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.root, &v.service, &v.kind, &v.cert, &v.fp); e != nil {
			rows.Close()
			return e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	// 换版、停用、撤销后取消尚未发送的旧提醒，不把历史证书当成待续期对象。
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.application_trust_reminders r SET state='superseded' WHERE environment=$1 AND state IN ('pending','sending') AND ((kind='service' AND NOT EXISTS(SELECT 1 FROM keygate.application_trust_services s JOIN keygate.application_trust_certificates c ON c.environment=s.environment AND c.service_id=s.service_id AND c.version=s.active_version WHERE s.environment=r.environment AND s.service_id=r.service_id AND NOT s.disabled AND c.state='active' AND c.fingerprint=r.fingerprint)) OR (kind='status' AND NOT EXISTS(SELECT 1 FROM keygate.application_trust_status_signers s WHERE s.environment=r.environment AND s.root_fingerprint=r.root_fingerprint AND s.fingerprint=r.fingerprint)))`, c.environment); e != nil {
		return e
	}
	for _, v := range items {
		info, e := certificateInfo(v.cert, now)
		if e != nil {
			return e
		}
		severity := reminderSeverity(info.NotAfter, now)
		if severity == "" {
			continue
		}
		// 只保留当前最高紧急级别，避免晚启动时补发已失效的较低级提醒。
		if _, e = tx.ExecContext(ctx, `UPDATE keygate.application_trust_reminders SET state='superseded' WHERE environment=$1 AND kind=$2 AND fingerprint=$3 AND severity<>$4 AND state IN ('pending','sending')`, c.environment, v.kind, v.fp, severity); e != nil {
			return e
		}
		id := trustchain.Fingerprint([]byte(c.environment + ":" + v.kind + ":" + v.fp + ":" + severity))
		result, e := tx.ExecContext(ctx, `INSERT INTO keygate.application_trust_reminders(id,environment,root_fingerprint,service_id,kind,fingerprint,expires_at,severity) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, id, c.environment, v.root, v.service, v.kind, v.fp, info.NotAfter, severity)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n > 0 {
			if e = c.audit(ctx, tx, "reminder-"+id[:24], "certificate-monitor", "application_trust_expiry", v.service, "queued"); e != nil {
				return e
			}
		}
	}
	return tx.Commit()
}
func (c *DevelopmentControl) TrustReminders(ctx context.Context, token string) ([]TrustReminder, error) {
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
	rows, e := tx.QueryContext(ctx, `SELECT id,root_fingerprint,service_id,kind,fingerprint,expires_at,severity,state,attempts FROM keygate.application_trust_reminders WHERE environment=$1 ORDER BY created_at DESC,id LIMIT 201`, c.environment)
	if e != nil {
		return nil, e
	}
	out := []TrustReminder{}
	for rows.Next() {
		v, e := scanReminder(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	return out, tx.Commit()
}

type reminderScanner interface{ Scan(...any) error }

func scanReminder(row reminderScanner) (TrustReminder, error) {
	var v TrustReminder
	e := row.Scan(&v.ID, &v.RootFingerprint, &v.ServiceID, &v.Kind, &v.Fingerprint, &v.ExpiresAt, &v.Severity, &v.State, &v.Attempts)
	return v, e
}

// DispatchTrustReminder 不持有数据库锁进行外部调用；租约与尝试编号防止迟到响应覆盖后续尝试。
// 超时结果不确定时按同一ID重试，邮件/短信插件必须自行保证幂等，不能宣称恰好一次投递。
func (c *DevelopmentControl) DispatchTrustReminder(ctx context.Context, plugin TrustReminderPlugin) (bool, error) {
	if plugin == nil {
		return false, ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	v, e := scanReminder(tx.QueryRowContext(ctx, `UPDATE keygate.application_trust_reminders SET state='sending',attempts=attempts+1,lease_until=clock_timestamp()+interval '60 seconds' WHERE id=(SELECT id FROM keygate.application_trust_reminders WHERE environment=$1 AND next_attempt<=clock_timestamp() AND (state='pending' OR (state='sending' AND lease_until<clock_timestamp())) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id,root_fingerprint,service_id,kind,fingerprint,expires_at,severity,state,attempts`, c.environment))
	if e == sql.ErrNoRows {
		return false, tx.Commit()
	}
	if e != nil {
		return false, e
	}
	if e = tx.Commit(); e != nil {
		return false, e
	}
	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	sendErr := plugin.SendTrustReminder(sendCtx, v)
	cancel()
	tx, e = c.begin(ctx)
	if e != nil {
		return true, e
	}
	defer tx.Rollback()
	state := "sent"
	if sendErr != nil {
		state = "pending"
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.application_trust_reminders SET state=$4,lease_until=NULL,next_attempt=clock_timestamp()+interval '5 minutes',sent_at=CASE WHEN $4='sent' THEN clock_timestamp() ELSE NULL END WHERE environment=$1 AND id=$2 AND attempts=$3 AND state='sending'`, c.environment, v.ID, v.Attempts, state)
	if e != nil {
		return true, e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return true, e
	}
	if n > 0 {
		if e = c.audit(ctx, tx, "reminder-"+v.ID[:24], "certificate-monitor", "application_trust_notification", v.ServiceID, state); e != nil {
			return true, e
		}
	}
	if e = tx.Commit(); e != nil {
		return true, e
	}
	if sendErr != nil {
		c.logger.WarnContext(ctx, "证书到期提醒发送失败，将按幂等键重试", "reminder_id", v.ID, "service_id", v.ServiceID, "attempt", v.Attempts)
	}
	return true, nil
}
