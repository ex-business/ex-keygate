-- 作用域审计和归档 outbox 与业务审计同事务写入，外部存储故障不拖住认证事务。
CREATE TABLE keygate.scoped_audit (
 event_id text PRIMARY KEY REFERENCES keygate.audit_events(event_id),
 environment text NOT NULL REFERENCES keygate.security_domains(environment), client_id text NOT NULL
);
CREATE INDEX scoped_audit_scope ON keygate.scoped_audit(environment,client_id,event_id);
CREATE TABLE keygate.audit_outbox (
 event_id text PRIMARY KEY REFERENCES keygate.scoped_audit(event_id), archived_hash text,
 archived_at timestamptz
);
CREATE FUNCTION keygate.audit_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO keygate.audit_outbox(event_id) VALUES(NEW.event_id);
 RETURN NEW;
END $$;
CREATE TRIGGER audit_outbox_insert AFTER INSERT ON keygate.scoped_audit FOR EACH ROW EXECUTE FUNCTION keygate.audit_enqueue();
CREATE TABLE keygate.audit_exports (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), export_id text NOT NULL,
 principal_id text NOT NULL, client_id text NOT NULL, payload bytea NOT NULL CHECK(octet_length(payload)<=8388608),
 digest text NOT NULL, event_count integer NOT NULL CHECK(event_count BETWEEN 0 AND 5000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes',
 PRIMARY KEY(environment,export_id)
);
CREATE TABLE keygate.auth_failure_buckets (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), minute timestamptz NOT NULL,
 reason text NOT NULL CHECK(reason IN ('denied','unavailable','rate_limited')),
 attempts bigint NOT NULL CHECK(attempts BETWEEN 1 AND 1000000000),
 PRIMARY KEY(environment,minute,reason)
);
