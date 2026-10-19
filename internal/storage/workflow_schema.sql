-- 新流程隔离旧草案和票，避免旧摘要迁移后继续充当授权。
CREATE TABLE keygate.control_requests (
 environment text NOT NULL REFERENCES keygate.security_domains(environment),
 request_id text NOT NULL, applicant_id text NOT NULL,
 manifest bytea NOT NULL CHECK(octet_length(manifest)<=65536),
 digest text NOT NULL CHECK(length(digest)=64),
 decision text NOT NULL DEFAULT 'pending' CHECK(decision IN ('pending','approved','rejected','cancelled')),
 expires_at timestamptz NOT NULL,
 executed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(environment,request_id),
 FOREIGN KEY(environment,applicant_id) REFERENCES keygate.principals(environment,principal_id)
);
CREATE TABLE keygate.control_votes (
 environment text NOT NULL, request_id text NOT NULL,
 principal_id text NOT NULL, person_id text NOT NULL,
 principal_revision bigint NOT NULL, grant_revision bigint NOT NULL, grant_scope text NOT NULL,
 accepted boolean NOT NULL, voted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,request_id,principal_id), UNIQUE(environment,request_id,person_id),
 FOREIGN KEY(environment,request_id) REFERENCES keygate.control_requests(environment,request_id),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.principals(environment,principal_id)
);
CREATE TABLE keygate.control_executions (
 environment text NOT NULL, request_id text NOT NULL,
 execution_id text NOT NULL UNIQUE, digest text NOT NULL,
 state text NOT NULL CHECK(state IN ('succeeded','failed','unknown')),
 PRIMARY KEY(environment,request_id),
 FOREIGN KEY(environment,request_id) REFERENCES keygate.control_requests(environment,request_id)
);
CREATE TABLE keygate.control_idempotency (
 environment text NOT NULL, principal_id text NOT NULL,
 idempotency_key text NOT NULL, parameters_digest text NOT NULL, request_id text NOT NULL,
 PRIMARY KEY(environment,principal_id,idempotency_key),
 FOREIGN KEY(environment,request_id) REFERENCES keygate.control_requests(environment,request_id)
);
