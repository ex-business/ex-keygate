CREATE TABLE keygate.provider_candidates (
 environment text NOT NULL REFERENCES keygate.security_domains(environment),provider_id text NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64),binding bytea NOT NULL CHECK(octet_length(binding)<=16384),
 implemented boolean NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,provider_id,digest)
);
CREATE TABLE keygate.provider_policies (
 environment text NOT NULL,provider_id text NOT NULL,active_digest text NOT NULL,
 enabled boolean NOT NULL DEFAULT false,revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 PRIMARY KEY(environment,provider_id),
 FOREIGN KEY(environment,provider_id,active_digest) REFERENCES keygate.provider_candidates(environment,provider_id,digest)
);
-- 未冻结插件修订的旧签发/激活票不能在迁移后继续扩大信任；已执行记录保持原事实。
UPDATE keygate.control_requests SET decision='cancelled' WHERE NOT executed AND convert_from(manifest,'UTF8')::jsonb->'operation'->>'kind' IN ('key_issue','key_activate','recovery_issue','recovery_activate','root_provision');
CREATE TABLE keygate.provider_checks (
 environment text NOT NULL,provider_id text NOT NULL,digest text NOT NULL,policy_revision bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('ready','unavailable','rejected')),conformance boolean NOT NULL,
 checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,provider_id),FOREIGN KEY(environment,provider_id) REFERENCES keygate.provider_policies(environment,provider_id)
);
