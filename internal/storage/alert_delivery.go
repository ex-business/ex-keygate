package storage

import (
	"context"
	"database/sql"
	"errors"
	"ex-keygate/internal/access"
	"time"
)

// AlertRoute 中的target是插件维护的收件组标识，不是可在线注入的URL或联系方式。
type AlertRoute struct {
	ID                string `json:"id"`
	Channel           string `json:"channel"`
	Target            string `json:"target"`
	Level             int    `json:"level"`
	EscalationSeconds int    `json:"escalationSeconds"`
	Digest            string `json:"-"`
}
type AlertMessage struct {
	ID         string    `json:"id"`
	IncidentID string    `json:"incidentId"`
	EventID    string    `json:"eventId"`
	RouteID    string    `json:"routeId"`
	Channel    string    `json:"channel"`
	Target     string    `json:"target"`
	Kind       string    `json:"kind"`
	Code       string    `json:"code"`
	NodeID     string    `json:"nodeId"`
	ObservedAt time.Time `json:"observedAt"`
	State      string    `json:"state"`
	Attempts   int       `json:"attempts"`
	CreatedAt  time.Time `json:"createdAt"`
	digest     string
}
type AlertPlugin interface {
	SendSystemAlert(context.Context, AlertMessage) error
}
type AlertBinding struct {
	Route  AlertRoute
	Plugin AlertPlugin
}
type AlertSilence struct {
	Code    string    `json:"code"`
	Until   time.Time `json:"until"`
	ActorID string    `json:"actorId"`
	Reason  string    `json:"reason"`
}
type AlertRecord struct {
	DeliveryID string     `json:"deliveryId"`
	Attempt    int        `json:"attempt"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	Outcome    string     `json:"outcome"`
}
type AlertDeliveryView struct {
	Routes     []AlertRoute   `json:"routes"`
	Silences   []AlertSilence `json:"silences"`
	Deliveries []AlertMessage `json:"deliveries"`
	Records    []AlertRecord  `json:"records"`
}

func validAlertRoute(r AlertRoute) bool {
	return access.ValidID(r.ID) && access.ValidID(r.Target) && (r.Channel == "email" || r.Channel == "sms" || r.Channel == "webhook") && validDigest(r.Digest) && ((r.Level == 0 && r.EscalationSeconds == 0) || (r.Level == 1 && r.EscalationSeconds >= 60 && r.EscalationSeconds <= 86400))
}

// ConfigureAlertRoutes 仅由启动器从受控离线配置安装，域锁和节点隔离避免旧发布覆盖新路由；更改路由使旧任务失效。
func (c *DevelopmentControl) ConfigureAlertRoutes(ctx context.Context, routes []AlertRoute) error {
	if len(routes) > 12 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	primary := false
	for _, r := range routes {
		if !validAlertRoute(r) || seen[r.ID] {
			return ErrInvalid
		}
		seen[r.ID] = true
		if r.Level == 0 {
			primary = true
		}
	}
	if len(routes) > 0 && !primary {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_routes SET enabled=false WHERE environment=$1`, c.environment); e != nil {
		return e
	}
	for _, r := range routes {
		_, e = tx.ExecContext(ctx, `INSERT INTO keygate.alert_routes(environment,id,channel,target,level,escalation_seconds,digest,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,true) ON CONFLICT(environment,id) DO UPDATE SET channel=EXCLUDED.channel,target=EXCLUDED.target,level=EXCLUDED.level,escalation_seconds=EXCLUDED.escalation_seconds,enabled=true,starts_at=CASE WHEN alert_routes.digest<>EXCLUDED.digest THEN clock_timestamp() ELSE alert_routes.starts_at END,digest=EXCLUDED.digest`, c.environment, r.ID, r.Channel, r.Target, r.Level, r.EscalationSeconds, r.Digest)
		if e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_deliveries j SET state='obsolete',lease_until=NULL WHERE j.environment=$1 AND j.state IN ('pending','sending','failed') AND NOT EXISTS(SELECT 1 FROM keygate.alert_routes r WHERE r.environment=j.environment AND r.id=j.route_id AND r.enabled AND r.digest=j.route_digest)`, c.environment); e != nil {
		return e
	}
	return tx.Commit()
}

func (c *DevelopmentControl) enqueueAlert(ctx context.Context, tx *sql.Tx, incident, event, code, node, kind string, at time.Time, level int) error {
	// 去重约束覆盖多节点扫描；消息载荷在生成时冻结，重试不会改变幂等键对应的内容。
	_, e := tx.ExecContext(ctx, `INSERT INTO keygate.alert_deliveries(environment,id,incident_id,event_id,route_id,route_digest,channel,target,kind,code,node_id,observed_at)
 SELECT $1,encode(sha256(convert_to($1||'/'||$2||'/'||r.id||'/'||$6,'UTF8')),'hex'),$3,$2,r.id,r.digest,r.channel,r.target,$6,$4,$5,$7 FROM keygate.alert_routes r WHERE r.environment=$1 AND r.enabled AND r.level=$8 AND r.starts_at<=$7
 ON CONFLICT(environment,event_id,route_id,kind) DO NOTHING`, c.environment, event, incident, code, node, kind, at, level)
	return e
}

// CollectAlertDeliveries 顺序消费事件，恢复关闭对应节点/代码的事故；外部I/O不在本事务中执行。
func (c *DevelopmentControl) CollectAlertDeliveries(ctx context.Context) error {
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.alert_delivery_cursor(environment) VALUES($1) ON CONFLICT DO NOTHING`, c.environment); e != nil {
		return e
	}
	var cursor int64
	if e = tx.QueryRowContext(ctx, `SELECT sequence FROM keygate.alert_delivery_cursor WHERE environment=$1 FOR UPDATE`, c.environment).Scan(&cursor); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, `SELECT sequence,event_id,code,node_id,active,recorded_at FROM keygate.system_monitor_events WHERE environment=$1 AND sequence>$2 ORDER BY sequence LIMIT 100`, c.environment, cursor)
	if e != nil {
		return e
	}
	type event struct {
		seq            int64
		id, code, node string
		active         bool
		at             time.Time
	}
	events := []event{}
	for rows.Next() {
		var v event
		if e = rows.Scan(&v.seq, &v.id, &v.code, &v.node, &v.active, &v.at); e != nil {
			rows.Close()
			return e
		}
		events = append(events, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range events {
		if v.active {
			// 同一作用域重复故障不新开事故；恢复后再次故障才生成新的独立通知。
			var exists bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.alert_incidents WHERE environment=$1 AND code=$2 AND node_id=$3 AND active)`, c.environment, v.code, v.node).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.alert_incidents(environment,id,code,node_id,opened_at,active) VALUES($1,$2,$3,$4,$5,true)`, c.environment, v.id, v.code, v.node, v.at); e != nil {
					return e
				}
				if e = c.enqueueAlert(ctx, tx, v.id, v.id, v.code, v.node, "trigger", v.at, 0); e != nil {
					return e
				}
			}
		} else {
			var incident string
			e = tx.QueryRowContext(ctx, `UPDATE keygate.alert_incidents SET active=false WHERE environment=$1 AND code=$2 AND node_id=$3 AND active RETURNING id`, c.environment, v.code, v.node).Scan(&incident)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if e == nil {
				if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_deliveries SET state='obsolete',lease_until=NULL WHERE environment=$1 AND incident_id=$2 AND kind<>'recovery' AND state IN ('pending','sending','failed')`, c.environment, incident); e != nil {
					return e
				}
				if e = c.enqueueAlert(ctx, tx, incident, v.id, v.code, v.node, "recovery", v.at, 0); e != nil {
					return e
				}
				// 升级对象只在已存在升级通知时收到恢复，避免向从未升级的组发送孤立恢复消息。
				_, e = tx.ExecContext(ctx, `INSERT INTO keygate.alert_deliveries(environment,id,incident_id,event_id,route_id,route_digest,channel,target,kind,code,node_id,observed_at) SELECT $1,encode(sha256(convert_to($1||'/'||$3||'/'||j.route_id||'/recovery','UTF8')),'hex'),$2,$3,j.route_id,j.route_digest,j.channel,j.target,'recovery',$4,$5,$6 FROM keygate.alert_deliveries j JOIN keygate.alert_routes r ON r.environment=j.environment AND r.id=j.route_id AND r.digest=j.route_digest AND r.enabled WHERE j.environment=$1 AND j.incident_id=$2 AND j.kind='escalation' ON CONFLICT DO NOTHING`, c.environment, incident, v.id, v.code, v.node, v.at)
				if e != nil {
					return e
				}
			}
		}
		cursor = v.seq
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_delivery_cursor SET sequence=$2 WHERE environment=$1`, c.environment, cursor); e != nil {
		return e
	}
	// 未恢复事故按数据库时间升级，即使初次投递失败也继续升级；每个事故/路由只生成一次。
	_, e = tx.ExecContext(ctx, `INSERT INTO keygate.alert_deliveries(environment,id,incident_id,event_id,route_id,route_digest,channel,target,kind,code,node_id,observed_at)
 SELECT $1,encode(sha256(convert_to($1||'/'||i.id||'/'||r.id||'/escalation','UTF8')),'hex'),i.id,i.id,r.id,r.digest,r.channel,r.target,'escalation',i.code,i.node_id,i.opened_at FROM keygate.alert_incidents i JOIN keygate.alert_routes r ON r.environment=i.environment AND r.enabled AND r.level=1 AND r.starts_at<=i.opened_at WHERE i.environment=$1 AND i.active AND i.opened_at+r.escalation_seconds*interval '1 second'<=clock_timestamp() ON CONFLICT DO NOTHING`, c.environment)
	if e != nil {
		return e
	}
	// 已崩溃发送者的最后一次尝试也必须收敛，不能永远停留在sending。
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_delivery_records d SET outcome='lease_expired',finished_at=clock_timestamp() FROM keygate.alert_deliveries j WHERE d.environment=$1 AND j.environment=d.environment AND j.id=d.delivery_id AND d.outcome='sending' AND (j.lease_until<clock_timestamp() OR j.state<>'sending')`, c.environment); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_deliveries SET state='failed',lease_until=NULL WHERE environment=$1 AND state='sending' AND attempts=5 AND lease_until<clock_timestamp()`, c.environment); e != nil {
		return e
	}
	return tx.Commit()
}

const alertColumns = `id,incident_id,event_id,route_id,route_digest,channel,target,kind,code,node_id,observed_at,state,attempts,created_at`

func scanAlert(row interface{ Scan(...any) error }) (AlertMessage, error) {
	var v AlertMessage
	e := row.Scan(&v.ID, &v.IncidentID, &v.EventID, &v.RouteID, &v.digest, &v.Channel, &v.Target, &v.Kind, &v.Code, &v.NodeID, &v.ObservedAt, &v.State, &v.Attempts, &v.CreatedAt)
	return v, e
}

// DispatchAlertDelivery 先领取30秒租约再调用插件，迟到确认必须同时匹配尝试编号和当前路由；无法保证网络恰好一次。
func (c *DevelopmentControl) DispatchAlertDelivery(ctx context.Context, bindings map[string]AlertBinding) (bool, error) {
	tx, e := c.begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	v, e := scanAlert(tx.QueryRowContext(ctx, `SELECT `+alertColumns+` FROM keygate.alert_deliveries WHERE environment=$1 AND attempts<5 AND next_attempt<=clock_timestamp() AND (state='pending' OR (state='sending' AND lease_until<clock_timestamp())) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, c.environment))
	if errors.Is(e, sql.ErrNoRows) {
		return false, tx.Commit()
	}
	if e != nil {
		return false, e
	}
	binding, ok := bindings[v.RouteID]
	if !ok || binding.Plugin == nil || binding.Route.Digest != v.digest || binding.Route.Channel != v.Channel || binding.Route.Target != v.Target {
		return false, ErrConflict
	}
	var allowed bool
	e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.alert_routes WHERE environment=$1 AND id=$2 AND digest=$3 AND enabled) AND ($4='recovery' OR EXISTS(SELECT 1 FROM keygate.alert_incidents WHERE environment=$1 AND id=$5 AND active) AND COALESCE((SELECT active FROM keygate.system_monitor_events WHERE environment=$1 AND code=$6 AND node_id=$7 ORDER BY sequence DESC LIMIT 1),false))`, c.environment, v.RouteID, v.digest, v.Kind, v.IncidentID, v.Code, v.NodeID).Scan(&allowed)
	if e != nil {
		return false, e
	}
	if !allowed {
		_, e = tx.ExecContext(ctx, `UPDATE keygate.alert_deliveries SET state='obsolete',lease_until=NULL WHERE environment=$1 AND id=$2`, c.environment, v.ID)
		if e != nil {
			return false, e
		}
		return true, tx.Commit()
	}
	var until time.Time
	e = tx.QueryRowContext(ctx, `SELECT until_at FROM keygate.alert_silences WHERE environment=$1 AND code=$2 AND until_at>clock_timestamp()`, c.environment, v.Code).Scan(&until)
	if e == nil {
		_, e = tx.ExecContext(ctx, `UPDATE keygate.alert_deliveries SET next_attempt=$3 WHERE environment=$1 AND id=$2`, c.environment, v.ID, until)
		if e != nil {
			return false, e
		}
		return true, tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return false, e
	}
	v.Attempts++
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_delivery_records SET outcome='lease_expired',finished_at=clock_timestamp() WHERE environment=$1 AND delivery_id=$2 AND outcome='sending'`, c.environment, v.ID); e != nil {
		return false, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_deliveries SET state='sending',attempts=$3,lease_until=clock_timestamp()+interval '30 seconds' WHERE environment=$1 AND id=$2`, c.environment, v.ID, v.Attempts); e != nil {
		return false, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.alert_delivery_records(environment,delivery_id,attempt,outcome) VALUES($1,$2,$3,'sending')`, c.environment, v.ID, v.Attempts); e != nil {
		return false, e
	}
	if e = tx.Commit(); e != nil {
		return false, e
	}
	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	sendErr := binding.Plugin.SendSystemAlert(sendCtx, v)
	cancel()
	tx, e = c.begin(ctx)
	if e != nil {
		return true, e
	}
	defer tx.Rollback()
	state := "sent"
	if sendErr != nil {
		state = "pending"
		if v.Attempts == 5 {
			state = "failed"
		}
	}
	result, e := tx.ExecContext(ctx, `UPDATE keygate.alert_deliveries SET state=$4,lease_until=NULL,next_attempt=clock_timestamp()+($3*$3*interval '30 seconds') WHERE environment=$1 AND id=$2 AND attempts=$3 AND state='sending' AND lease_until>clock_timestamp() AND EXISTS(SELECT 1 FROM keygate.alert_routes r WHERE r.environment=$1 AND r.id=route_id AND r.digest=route_digest AND r.enabled)`, c.environment, v.ID, v.Attempts, state)
	if e != nil {
		return true, e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return true, e
	}
	outcome := "obsolete"
	if n == 1 {
		outcome = "sent"
		if sendErr != nil {
			outcome = "unconfirmed"
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_delivery_records SET outcome=$4,finished_at=clock_timestamp() WHERE environment=$1 AND delivery_id=$2 AND attempt=$3 AND outcome='sending'`, c.environment, v.ID, v.Attempts, outcome); e != nil {
		return true, e
	}
	if e = tx.Commit(); e != nil {
		return true, e
	}
	if sendErr != nil {
		c.logger.WarnContext(ctx, "告警投递未确认，按原幂等标识重试或保留失败", "delivery_id", v.ID, "incident_id", v.IncidentID, "route_id", v.RouteID, "attempt", v.Attempts, "result", state)
	}
	return true, nil
}

// SetAlertSilence 全域策略管理员近期验证后方可静默，最多24小时；理由和操作者进入审计，零秒只解除现有静默。
func (c *DevelopmentControl) SetAlertSilence(ctx context.Context, token, code, reason, trace string, seconds int) error {
	if !access.ValidID(code) || !access.ValidID(trace) || !validGovernanceReason(reason) || seconds < 0 || seconds > 86400 {
		return ErrInvalid
	}
	tx, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := c.notificationOperator(ctx, tx, token, true)
	if e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM keygate.system_monitor_events WHERE environment=$1 AND code=$2) OR EXISTS(SELECT 1 FROM keygate.system_monitor_alerts WHERE environment=$1 AND code=$2)`, c.environment, code).Scan(&exists); e != nil {
		return e
	}
	if !exists {
		return ErrInvalid
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO keygate.alert_silences(environment,code,until_at,actor_id,reason) VALUES($1,$2,clock_timestamp()+$3*interval '1 second',$4,$5) ON CONFLICT(environment,code) DO UPDATE SET until_at=EXCLUDED.until_at,actor_id=EXCLUDED.actor_id,reason=EXCLUDED.reason`, c.environment, code, seconds, a.id, reason); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE keygate.alert_deliveries SET next_attempt=clock_timestamp() WHERE environment=$1 AND code=$2 AND state='pending'`, c.environment, code); e != nil {
		return e
	}
	action := "alert_silence"
	if seconds == 0 {
		action = "alert_unsilence"
	}
	if e = c.audit(ctx, tx, trace, a.id, action, code, "updated"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.logger.InfoContext(ctx, "告警静默设置已更新", "request_id", trace, "principal_id", a.id, "alert_code", code, "duration_seconds", seconds, "result", action)
	return nil
}

func (c *DevelopmentControl) AlertDeliveries(ctx context.Context, token string) (AlertDeliveryView, error) {
	out := AlertDeliveryView{Routes: []AlertRoute{}, Silences: []AlertSilence{}, Deliveries: []AlertMessage{}, Records: []AlertRecord{}}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, e := c.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if _, e = c.notificationOperator(ctx, tx, token, false); e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT id,channel,target,level,escalation_seconds FROM keygate.alert_routes WHERE environment=$1 AND enabled ORDER BY level,id`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var r AlertRoute
		if e = rows.Scan(&r.ID, &r.Channel, &r.Target, &r.Level, &r.EscalationSeconds); e != nil {
			rows.Close()
			return out, e
		}
		out.Routes = append(out.Routes, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.QueryContext(ctx, `SELECT code,until_at,actor_id,reason FROM keygate.alert_silences WHERE environment=$1 AND until_at>clock_timestamp() ORDER BY code LIMIT 100`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var r AlertSilence
		if e = rows.Scan(&r.Code, &r.Until, &r.ActorID, &r.Reason); e != nil {
			rows.Close()
			return out, e
		}
		out.Silences = append(out.Silences, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.QueryContext(ctx, `SELECT `+alertColumns+` FROM keygate.alert_deliveries WHERE environment=$1 ORDER BY created_at DESC,id DESC LIMIT 100`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		v, err := scanAlert(rows)
		if err != nil {
			rows.Close()
			return out, err
		}
		out.Deliveries = append(out.Deliveries, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.QueryContext(ctx, `SELECT delivery_id,attempt,started_at,finished_at,outcome FROM keygate.alert_delivery_records WHERE environment=$1 ORDER BY started_at DESC,delivery_id,attempt LIMIT 200`, c.environment)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var r AlertRecord
		if e = rows.Scan(&r.DeliveryID, &r.Attempt, &r.StartedAt, &r.FinishedAt, &r.Outcome); e != nil {
			rows.Close()
			return out, e
		}
		out.Records = append(out.Records, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}
