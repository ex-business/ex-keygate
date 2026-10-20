-- 证书变更事实与业务状态同事务写入；旧记录不伪造操作时间或撤销原因。
CREATE TABLE keygate.application_trust_changes (
 sequence bigserial PRIMARY KEY,
 environment text NOT NULL REFERENCES keygate.security_domains(environment),
 root_fingerprint text NOT NULL,
 service_id text NOT NULL,
 version bigint NOT NULL CHECK(version>0),
 revision bigint NOT NULL CHECK(revision>0),
 action text NOT NULL CHECK(action IN ('published','retired','disabled','revoked')),
 reason text NOT NULL,
 approval_id text NOT NULL,
 actor_id text NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(environment,service_id,version) REFERENCES keygate.application_trust_certificates(environment,service_id,version)
);
CREATE INDEX application_trust_changes_version ON keygate.application_trust_changes(environment,service_id,version,sequence DESC);
