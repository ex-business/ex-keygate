package storage

import (
	"ex-keygate/internal/access"
	"fmt"
	"strings"
)

// RestoreTransactionSQL 只生成当前已知结构的核对与隔离尾部，在pg_restore SQL与COMMIT之间由同一会话执行。
// 名称来自固定表白名单，值先验证再作为单引号字面量；检查失败必须抛异常使整个还原事务回滚。
func RestoreTransactionSQL(cp SafetyCheckpoint, trace string) (string, error) {
	if cp.Kind != "keygate-state-v1" || !access.ValidID(cp.ID) || !access.ValidID(cp.Environment) || !access.ValidID(trace) || len(cp.Tables) != len(checkpointTables) {
		return "", ErrInvalid
	}
	literal := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	environment := literal(cp.Environment)
	out := strings.Builder{}
	out.WriteString("SET LOCAL TIME ZONE 'UTC';\nDO $keygate_restore_verify$ BEGIN\n")
	for _, table := range checkpointTables {
		expected, ok := cp.Tables[table.name]
		if !ok || expected.Count < 0 || !validDigest(expected.Digest) {
			return "", ErrInvalid
		}
		where := strings.ReplaceAll(table.where, "$1", environment)
		// 单表聚合超过PostgreSQL容量或内存限制会拒绝恢复并回滚，不能跳过摘要验证继续提交。
		fmt.Fprintf(&out, "IF (SELECT count(*)<>%d OR encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(x)::text || E'\\n','' ORDER BY to_jsonb(x)::text COLLATE \\\"C\\\"),''),'UTF8')),'hex')<>%s FROM (SELECT * FROM keygate.%s WHERE %s) x) THEN RAISE EXCEPTION 'restore checkpoint mismatch'; END IF;\n", expected.Count, literal(expected.Digest), table.name, where)
	}
	out.WriteString("END; $keygate_restore_verify$;\n")
	for _, statement := range quarantineStatements(RuntimeSchemaVersion) {
		out.WriteString(strings.ReplaceAll(statement, "$1", environment) + ";\n")
	}
	event, e := controlID()
	if e != nil {
		return "", e
	}
	fmt.Fprintf(&out, "INSERT INTO keygate.audit_events(event_id,request_id,actor_id,action,target_id,result) VALUES(%s,%s,'offline-recovery','restore_quarantine',%s,'disabled');\nINSERT INTO keygate.scoped_audit(event_id,environment,client_id) VALUES(%s,%s,'');\n", literal(event), literal(trace), literal(cp.ID), literal(event), environment)
	out.WriteString("DO $keygate_restore_isolation$ BEGIN IF NOT (" + strings.ReplaceAll(quarantinedQuery, "$1", environment) + ") THEN RAISE EXCEPTION 'restore isolation failed'; END IF; END; $keygate_restore_isolation$;\n")
	return strings.ReplaceAll(out.String(), `\"C\"`, `"C"`), nil
}

func quarantineStatements(schemaVersion int) []string {
	statements := []string{`UPDATE keygate.runtime_cluster SET generation=generation+1 WHERE singleton`}
	if schemaVersion >= 25 {
		statements = append(statements,
			`UPDATE keygate.alert_deliveries SET state='obsolete',lease_until=NULL WHERE environment=$1 AND state IN ('pending','sending','failed')`,
			`UPDATE keygate.alert_delivery_records SET outcome='obsolete',finished_at=clock_timestamp() WHERE environment=$1 AND outcome='sending'`,
			`UPDATE keygate.alert_incidents SET active=false WHERE environment=$1 AND active`,
			`DELETE FROM keygate.alert_silences WHERE environment=$1`,
			`UPDATE keygate.alert_routes SET starts_at=clock_timestamp() WHERE environment=$1`,
			`INSERT INTO keygate.alert_delivery_cursor(environment,sequence) SELECT $1,COALESCE(max(sequence),0) FROM keygate.system_monitor_events WHERE environment=$1 ON CONFLICT(environment) DO UPDATE SET sequence=EXCLUDED.sequence`)
	}
	if schemaVersion >= 24 {
		statements = append(statements, `DELETE FROM keygate.system_monitor_samples WHERE environment=$1`, `UPDATE keygate.system_monitor_alerts SET active=false,count=0,changed_at=clock_timestamp() WHERE environment=$1`)
	}
	if schemaVersion >= 22 {
		statements = append(statements, `UPDATE keygate.approval_notifications SET state='obsolete',lease_until=NULL WHERE environment=$1 AND state IN ('pending','sending')`)
	}
	return append(statements,
		`UPDATE keygate.account_setups SET consumed=true WHERE environment=$1 AND NOT consumed`,
		`DELETE FROM keygate.mfa_challenges WHERE environment=$1`, `DELETE FROM keygate.mfa_proofs WHERE environment=$1`,
		`UPDATE keygate.application_trust_services SET disabled=true,revision=revision+1 WHERE environment=$1`,
		`UPDATE keygate.browser_sessions SET revoked_at=clock_timestamp() WHERE environment=$1 AND revoked_at IS NULL`,
		`UPDATE keygate.provider_policies SET enabled=false,revision=revision+1 WHERE environment=$1`,
		`UPDATE keygate.clients SET state='disabled',revision=revision+1 WHERE environment=$1`,
		`UPDATE keygate.control_requests SET decision='cancelled' WHERE environment=$1 AND NOT executed`,
		`UPDATE keygate.sessions SET revoked_at=clock_timestamp() WHERE principal_id IN(SELECT principal_id FROM keygate.principals WHERE environment=$1) AND revoked_at IS NULL`,
		`UPDATE keygate.client_roots SET enabled=false WHERE environment=$1`,
		`UPDATE keygate.key_versions SET state='compromised' WHERE environment=$1 AND state<>'compromised'`,
		`UPDATE keygate.recovery_tasks SET state='aborted',finished_at=clock_timestamp() WHERE environment=$1 AND state IN ('preparing','staged')`,
		`UPDATE keygate.rotation_tasks SET state='failed',completed_at=clock_timestamp() WHERE environment=$1 AND state IN ('preparing','overlap')`,
		`UPDATE keygate.audit_exports SET payload=''::bytea,expires_at=LEAST(expires_at,clock_timestamp()) WHERE environment=$1`)
}
