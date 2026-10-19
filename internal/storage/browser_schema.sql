-- H5 会话只保存随机凭据摘要，绑定身份会话、客户端及人员修订，不引入浏览器共享密钥。
CREATE TABLE keygate.browser_sessions (
 token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32),
 environment text NOT NULL,
 client_id text NOT NULL,
 principal_id text NOT NULL,
 identity_hash bytea NOT NULL REFERENCES keygate.sessions(token_hash),
 profile_hash text NOT NULL CHECK(length(profile_hash)=64),
 client_revision bigint NOT NULL CHECK(client_revision>0),
 principal_revision bigint NOT NULL CHECK(principal_revision>0),
 authenticated_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 FOREIGN KEY(environment,client_id) REFERENCES keygate.clients(environment,client_id),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.principals(environment,principal_id),
 CHECK(expires_at>authenticated_at)
);
CREATE INDEX browser_session_parent ON keygate.browser_sessions(environment,client_id,identity_hash) WHERE revoked_at IS NULL;
CREATE INDEX browser_session_expiry ON keygate.browser_sessions(expires_at);
ALTER TABLE keygate.login_states ADD COLUMN browser_context bytea CHECK(browser_context IS NULL OR octet_length(browser_context)<=2048);
