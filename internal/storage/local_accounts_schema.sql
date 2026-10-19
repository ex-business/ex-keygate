-- 本地账号仅绑定受控离线核验的已有人员；口令阶段不产生MFA证明。
CREATE TABLE keygate.local_accounts (
 environment text NOT NULL,
 username text NOT NULL CHECK(username ~ '^[a-z0-9][a-z0-9._@-]{2,127}$'),
 principal_id text NOT NULL,
 password_hash text NOT NULL CHECK(length(password_hash)<256),
 failures integer NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5),
 locked_until timestamptz NOT NULL DEFAULT '-infinity',
 enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(environment,username),
 UNIQUE(environment,principal_id),
 FOREIGN KEY(environment,principal_id) REFERENCES keygate.principals(environment,principal_id)
);
-- 每个安全域只有一个共享预算行，未知账号不能制造无界限流数据。
CREATE TABLE keygate.local_login_budget (
 environment text PRIMARY KEY REFERENCES keygate.security_domains(environment),
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts integer NOT NULL DEFAULT 0
);
-- 认证来源持久化，待MFA的密码会话不得通过H5身份兑换绕过验证。
ALTER TABLE keygate.sessions ADD COLUMN local_password boolean NOT NULL DEFAULT false;
