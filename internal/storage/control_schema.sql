-- 本迁移只添加独立授权域；旧开发审批不会作为新授权流程的输入。
CREATE TABLE keygate.security_domains (
 environment text PRIMARY KEY CHECK (environment ~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$'),
 revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
 bootstrap_evidence_hash text NOT NULL CHECK(length(bootstrap_evidence_hash)=64),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE keygate.principals (
 environment text NOT NULL REFERENCES keygate.security_domains(environment),
 principal_id text NOT NULL CHECK(length(principal_id)=69),
 issuer text NOT NULL,
 subject_hash text NOT NULL CHECK(length(subject_hash)=64),
 person_id text NOT NULL,
 enabled boolean NOT NULL DEFAULT true,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 PRIMARY KEY(environment,principal_id), UNIQUE(environment,issuer,subject_hash)
);
CREATE TABLE keygate.role_grants (
 environment text NOT NULL, principal_id text NOT NULL,
 role text NOT NULL CHECK(role IN ('viewer','requester','approver','policy_admin','auditor','emergency_operator')),
 client_id text NOT NULL DEFAULT '', enabled boolean NOT NULL DEFAULT true,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 PRIMARY KEY(environment,principal_id,role,client_id),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.principals(environment,principal_id)
);
CREATE TABLE keygate.auth_profiles (
 environment text NOT NULL REFERENCES keygate.security_domains(environment),
 profile_id text NOT NULL, version bigint NOT NULL CHECK(version>0),
 client_type text NOT NULL CHECK(client_type IN ('backend','desktop','mobile','browser')),
 method text NOT NULL, storage text NOT NULL, provider_id text NOT NULL,
 enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(environment,profile_id,version), UNIQUE(environment,profile_id,version,client_type)
);
CREATE TABLE keygate.clients (
 environment text NOT NULL, client_id text NOT NULL,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 client_type text NOT NULL,
 profile_id text NOT NULL, profile_version bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('enabled','disabled')),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 PRIMARY KEY(environment,client_id),
 FOREIGN KEY(environment,profile_id,profile_version,client_type) REFERENCES keygate.auth_profiles(environment,profile_id,version,client_type)
);
CREATE TABLE keygate.control_policies (
 environment text PRIMARY KEY REFERENCES keygate.security_domains(environment),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 threshold integer NOT NULL CHECK(threshold>=2 AND threshold<=32)
);
CREATE TABLE keygate.control_policy_members (
 environment text NOT NULL REFERENCES keygate.control_policies(environment),
 principal_id text NOT NULL,
 PRIMARY KEY(environment,principal_id),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.principals(environment,principal_id)
);
