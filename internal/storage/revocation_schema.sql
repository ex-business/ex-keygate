-- 撤销是终态事实；即使旧审批或晚到任务重试也不能覆盖。
CREATE TABLE keygate.revocations (
 environment text NOT NULL REFERENCES keygate.security_domains(environment),
 incident_id text NOT NULL, client_id text NOT NULL, key_version bigint NOT NULL,
 root_id text NOT NULL, reason text NOT NULL, actor_id text NOT NULL,
 parameters_digest text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,incident_id)
);
CREATE FUNCTION keygate.guard_compromised() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.state='compromised' AND NEW.state<>'compromised' THEN
  RAISE EXCEPTION 'revoked version is terminal';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER compromised_terminal BEFORE UPDATE ON keygate.key_versions FOR EACH ROW EXECUTE FUNCTION keygate.guard_compromised();
