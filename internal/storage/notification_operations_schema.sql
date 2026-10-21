ALTER TABLE keygate.approval_notifications ADD COLUMN resend_count integer NOT NULL DEFAULT 0 CHECK(resend_count BETWEEN 0 AND 3), ADD COLUMN last_resend_at timestamptz;
CREATE TABLE keygate.approval_delivery_records (
 environment text NOT NULL, notification_id text NOT NULL, round integer NOT NULL, attempt integer NOT NULL,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), finished_at timestamptz,
 outcome text NOT NULL CHECK(outcome IN ('sending','sent','unconfirmed','lease_expired','obsolete','rescheduled')),
 actor_id text NOT NULL DEFAULT '', reason text NOT NULL DEFAULT '',
 PRIMARY KEY(environment,notification_id,round,attempt),
 FOREIGN KEY(environment,notification_id) REFERENCES keygate.approval_notifications(environment,id)
);
CREATE TABLE keygate.approval_notification_alerts (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), code text NOT NULL,
 active boolean NOT NULL, count bigint NOT NULL, oldest_seconds bigint NOT NULL,
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(), checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,code)
);
CREATE INDEX approval_notice_operations ON keygate.approval_notifications(environment,state,created_at DESC,id);
