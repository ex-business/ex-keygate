-- 持久部署绑定原管理域、登录配置及发布代次；正常启动只能读取，不能借缺失状态重新初始化。
CREATE TABLE keygate.persistent_deployments (
 environment text PRIMARY KEY REFERENCES keygate.security_domains(environment),
 deployment_id text NOT NULL UNIQUE, revision bigint NOT NULL CHECK(revision>0),
 config_hash text NOT NULL CHECK(length(config_hash)=64), profile_hash text NOT NULL CHECK(length(profile_hash)=64),
 protocol integer NOT NULL CHECK(protocol>0), schema_version integer NOT NULL CHECK(schema_version>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
