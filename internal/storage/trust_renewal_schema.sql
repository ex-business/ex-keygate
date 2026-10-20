-- 状态签名证书是根下共享能力，切换事实和当前指针必须与审批执行同事务提交。
CREATE TABLE keygate.application_trust_status_signers (
 environment text NOT NULL, root_fingerprint text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), fingerprint text NOT NULL,
 certificate bytea NOT NULL CHECK(octet_length(certificate)<=16384),
 PRIMARY KEY(environment,root_fingerprint),
 FOREIGN KEY(environment,root_fingerprint) REFERENCES keygate.application_trust_roots(environment,fingerprint)
);
CREATE TABLE keygate.application_trust_status_changes (
 sequence bigserial PRIMARY KEY, environment text NOT NULL, root_fingerprint text NOT NULL,
 revision bigint NOT NULL, fingerprint text NOT NULL, certificate bytea NOT NULL,
 approval_id text NOT NULL, actor_id text NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(environment,root_fingerprint,fingerprint)
);
-- 相同证书、提醒级别只创建一次；插件必须以id作为幂等键，超时重试不承诺恰好一次。
CREATE TABLE keygate.application_trust_reminders (
 id text PRIMARY KEY, environment text NOT NULL, root_fingerprint text NOT NULL,
 service_id text NOT NULL, kind text NOT NULL, fingerprint text NOT NULL,
 expires_at timestamptz NOT NULL, severity text NOT NULL CHECK(severity IN ('due_7d','due_24h','due_1h','expired')),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sending','sent','superseded')),
 attempts integer NOT NULL DEFAULT 0, next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_until timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), sent_at timestamptz,
 UNIQUE(environment,kind,fingerprint,severity)
);
