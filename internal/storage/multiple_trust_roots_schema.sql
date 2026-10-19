-- 保留既有根与服务绑定；根指纹参与主键，业务服务标识仍在管理域内唯一。
ALTER TABLE keygate.application_trust_services DROP CONSTRAINT application_trust_services_environment_fkey;
ALTER TABLE keygate.application_trust_services ADD COLUMN root_fingerprint text;
UPDATE keygate.application_trust_services s SET root_fingerprint=r.fingerprint FROM keygate.application_trust_roots r WHERE s.environment=r.environment;
ALTER TABLE keygate.application_trust_services ALTER COLUMN root_fingerprint SET NOT NULL;
ALTER TABLE keygate.application_trust_roots DROP CONSTRAINT application_trust_roots_pkey;
ALTER TABLE keygate.application_trust_roots ADD PRIMARY KEY(environment,fingerprint);
ALTER TABLE keygate.application_trust_services ADD FOREIGN KEY(environment,root_fingerprint) REFERENCES keygate.application_trust_roots(environment,fingerprint);
-- 旧节点仍可向单根域发布服务；多根域必须显式声明根，禁止默认猜测。
CREATE FUNCTION keygate.bind_application_trust_root() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE root_count integer;
BEGIN
 IF TG_OP='UPDATE' AND NEW.root_fingerprint IS DISTINCT FROM OLD.root_fingerprint THEN
  RAISE EXCEPTION '业务服务不允许通过普通更新更换信任根';
 END IF;
 IF NEW.root_fingerprint IS NULL THEN
  SELECT count(*),min(fingerprint) INTO root_count,NEW.root_fingerprint FROM keygate.application_trust_roots WHERE environment=NEW.environment;
  IF root_count<>1 THEN RAISE EXCEPTION '多根管理域必须显式绑定根指纹'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER bind_application_trust_root BEFORE INSERT OR UPDATE ON keygate.application_trust_services FOR EACH ROW EXECUTE FUNCTION keygate.bind_application_trust_root();
