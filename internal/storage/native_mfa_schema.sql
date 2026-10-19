-- 原生MFA在权威库内绑定身份会话、人员修订、策略修订及唯一绑定项；默认旧域不隐式启用。
ALTER TABLE keygate.security_domains ADD COLUMN native_mfa_required boolean NOT NULL DEFAULT false;
CREATE TABLE keygate.mfa_policies (
 environment text NOT NULL REFERENCES keygate.security_domains(environment),
 principal_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 last_started timestamptz,
 policy bytea NOT NULL CHECK(octet_length(policy)<=8192),
 PRIMARY KEY(environment,principal_id),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.principals(environment,principal_id)
);
CREATE TABLE keygate.mfa_factors (
 environment text NOT NULL,principal_id text NOT NULL,factor_id text NOT NULL,
 method text NOT NULL CHECK(method IN ('email','sms','totp','hardware')),
 label text NOT NULL,reference text NOT NULL,secret_cipher bytea,
 fingerprint text NOT NULL CHECK(length(fingerprint)=64),
 last_counter bigint NOT NULL DEFAULT -1,
 tries integer NOT NULL DEFAULT 0, tries_until timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,principal_id,factor_id),
 UNIQUE(environment,fingerprint),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.mfa_policies(environment,principal_id)
);
CREATE TABLE keygate.mfa_challenges (
 environment text NOT NULL,challenge_id text NOT NULL,principal_id text NOT NULL,
 session_hash bytea NOT NULL REFERENCES keygate.sessions(token_hash),
 purpose text NOT NULL,policy_revision bigint NOT NULL,principal_revision bigint NOT NULL,
 expires_at timestamptz NOT NULL,completed_at timestamptz,
 PRIMARY KEY(environment,challenge_id),
 UNIQUE(environment,session_hash,purpose),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.mfa_policies(environment,principal_id)
);
CREATE TABLE keygate.mfa_attempts (
 environment text NOT NULL,challenge_id text NOT NULL,factor_id text NOT NULL,
 attempt_id text NOT NULL,nonce text NOT NULL,verifier_cipher bytea,code_digest bytea,
 delivered boolean NOT NULL DEFAULT false,tries integer NOT NULL DEFAULT 0 CHECK(tries BETWEEN 0 AND 5),
 verified boolean NOT NULL DEFAULT false,expires_at timestamptz NOT NULL,
 PRIMARY KEY(environment,challenge_id,factor_id),UNIQUE(attempt_id),
 FOREIGN KEY(environment,challenge_id) REFERENCES keygate.mfa_challenges(environment,challenge_id) ON DELETE CASCADE
);
CREATE TABLE keygate.mfa_proofs (
 environment text NOT NULL,session_hash bytea NOT NULL REFERENCES keygate.sessions(token_hash),
 purpose text NOT NULL,principal_id text NOT NULL,principal_revision bigint NOT NULL,policy_revision bigint NOT NULL,
 verified_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 PRIMARY KEY(environment,session_hash,purpose),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.mfa_policies(environment,principal_id)
);
CREATE INDEX mfa_challenge_expiry ON keygate.mfa_challenges(expires_at);

ALTER TABLE keygate.control_policies ADD COLUMN sequential boolean NOT NULL DEFAULT false;
ALTER TABLE keygate.control_policy_members ADD COLUMN ordinal integer NOT NULL DEFAULT 0;

CREATE TABLE keygate.control_skips (
 environment text NOT NULL,request_id text NOT NULL,principal_id text NOT NULL,person_id text NOT NULL,
 principal_revision bigint NOT NULL,grant_revision bigint NOT NULL,grant_scope text NOT NULL,
 reason text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,request_id,principal_id),UNIQUE(environment,request_id,person_id),
 FOREIGN KEY(environment,request_id) REFERENCES keygate.control_requests(environment,request_id)
);
