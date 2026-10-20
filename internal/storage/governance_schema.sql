-- 按域明确封禁人员调整前已存在的会话，不能使用外部auth_time推断服务端发行顺序。
CREATE TABLE keygate.principal_session_blocks (
 environment text NOT NULL REFERENCES keygate.security_domains(environment),
 token_hash bytea NOT NULL REFERENCES keygate.sessions(token_hash) ON DELETE CASCADE,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,token_hash)
);
