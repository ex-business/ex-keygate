-- 告警投递仅保存经离线配置批准的路由标识，不接受在线URL、电话或邮件地址。
CREATE TABLE keygate.alert_routes (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), id text NOT NULL,
 channel text NOT NULL CHECK(channel IN ('email','sms','webhook')), target text NOT NULL,
 level integer NOT NULL CHECK(level IN (0,1)), escalation_seconds integer NOT NULL,
 digest text NOT NULL, enabled boolean NOT NULL, starts_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,id)
);
CREATE TABLE keygate.alert_delivery_cursor (
 environment text PRIMARY KEY REFERENCES keygate.security_domains(environment), sequence bigint NOT NULL DEFAULT 0
);
CREATE TABLE keygate.alert_incidents (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), id text NOT NULL,
 code text NOT NULL,node_id text NOT NULL, opened_at timestamptz NOT NULL, active boolean NOT NULL,
 PRIMARY KEY(environment,id)
);
CREATE INDEX alert_incident_scope ON keygate.alert_incidents(environment,code,node_id,active);
CREATE TABLE keygate.alert_silences (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), code text NOT NULL,
 until_at timestamptz NOT NULL, actor_id text NOT NULL, reason text NOT NULL,
 PRIMARY KEY(environment,code)
);
CREATE TABLE keygate.alert_deliveries (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), id text NOT NULL,
 incident_id text NOT NULL, event_id text NOT NULL, route_id text NOT NULL, route_digest text NOT NULL,
 channel text NOT NULL,target text NOT NULL,kind text NOT NULL CHECK(kind IN ('trigger','recovery','escalation')),
 code text NOT NULL,node_id text NOT NULL,observed_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sending','sent','failed','suppressed','obsolete')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5), next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_until timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,id),UNIQUE(environment,event_id,route_id,kind)
);
CREATE INDEX alert_delivery_work ON keygate.alert_deliveries(environment,state,next_attempt);
CREATE TABLE keygate.alert_delivery_records (
 environment text NOT NULL, delivery_id text NOT NULL,attempt integer NOT NULL,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), finished_at timestamptz,
 outcome text NOT NULL CHECK(outcome IN ('sending','sent','unconfirmed','lease_expired','obsolete')),
 PRIMARY KEY(environment,delivery_id,attempt),
 FOREIGN KEY(environment,delivery_id) REFERENCES keygate.alert_deliveries(environment,id)
);
