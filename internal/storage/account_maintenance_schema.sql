ALTER TABLE keygate.local_accounts ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK(revision>0);
-- 审批中只出现公开方案及高熵交付码的摘要，交付码和新密码不落明文。
CREATE TABLE keygate.account_setups (
 environment text NOT NULL, setup_id text NOT NULL, target text NOT NULL,
 token_hash text NOT NULL CHECK(length(token_hash)=64), request_id text NOT NULL,
 expires_at timestamptz NOT NULL, consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(environment,setup_id), UNIQUE(environment,token_hash),
 FOREIGN KEY(environment,request_id) REFERENCES keygate.control_requests(environment,request_id),
 FOREIGN KEY(environment,target) REFERENCES keygate.principals(environment,principal_id)
);
CREATE TABLE keygate.account_setup_factors (
 environment text NOT NULL,setup_id text NOT NULL,factor_id text NOT NULL,
 method text NOT NULL,label text NOT NULL,reference text NOT NULL,
 secret_cipher bytea, fingerprint text NOT NULL, verifier_cipher bytea,
 prepared boolean NOT NULL DEFAULT false, verified boolean NOT NULL DEFAULT false, delivered boolean NOT NULL DEFAULT false,
 tries integer NOT NULL DEFAULT 0 CHECK(tries BETWEEN 0 AND 5), sends integer NOT NULL DEFAULT 0 CHECK(sends BETWEEN 0 AND 3), last_counter bigint NOT NULL DEFAULT -1,
 PRIMARY KEY(environment,setup_id,factor_id),UNIQUE(environment,setup_id,fingerprint),
 FOREIGN KEY(environment,setup_id) REFERENCES keygate.account_setups(environment,setup_id)
);
