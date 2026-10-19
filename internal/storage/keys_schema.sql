-- 仅开发软件客户端密钥；不保存根秘密或客户端明文。
CREATE TABLE keygate.client_roots (
 root_id text PRIMARY KEY REFERENCES keygate.root_budgets(root_id),
 environment text NOT NULL REFERENCES keygate.security_domains(environment),
 purpose text NOT NULL CHECK(purpose='client_auth'), key_fingerprint text NOT NULL UNIQUE CHECK(length(key_fingerprint)=64), enabled boolean NOT NULL DEFAULT true,
 UNIQUE(environment,root_id)
);
CREATE TABLE keygate.key_versions (
 environment text NOT NULL, client_id text NOT NULL, version bigint NOT NULL CHECK(version>0),
 state text NOT NULL CHECK(state IN ('pending','staged','active','retiring','disabled','expired','compromised')),
 root_id text NOT NULL, format text NOT NULL, ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)=60),
 not_before timestamptz NOT NULL, not_after timestamptz NOT NULL CHECK(not_after>not_before),
 issue_id text NOT NULL, recipient_der bytea NOT NULL, recipient_fingerprint text NOT NULL CHECK(length(recipient_fingerprint)=64),
 recipient_signing_der bytea NOT NULL, recipient_signing_fingerprint text NOT NULL CHECK(length(recipient_signing_fingerprint)=64),
 delivery_ciphertext bytea NOT NULL CHECK(octet_length(delivery_ciphertext) IN (384,512)),
 claim_nonce bytea NOT NULL CHECK(octet_length(claim_nonce)=32),
 proof_nonce bytea NOT NULL CHECK(octet_length(proof_nonce)=32),
 claim_expires timestamptz NOT NULL, claimed_at timestamptz,
 PRIMARY KEY(environment,client_id,version), UNIQUE(environment,issue_id),
 FOREIGN KEY(environment,client_id) REFERENCES keygate.clients(environment,client_id),
 FOREIGN KEY(environment,root_id) REFERENCES keygate.client_roots(environment,root_id),
 FOREIGN KEY(environment,issue_id) REFERENCES keygate.control_requests(environment,request_id)
);
CREATE UNIQUE INDEX one_active_key ON keygate.key_versions(environment,client_id) WHERE state='active';
CREATE UNIQUE INDEX one_retiring_key ON keygate.key_versions(environment,client_id) WHERE state='retiring';
