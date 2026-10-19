-- 生命周期事实与密文分离，永久保留原有效期和批准的过渡截止时间。
ALTER TABLE keygate.key_versions ADD COLUMN original_not_after timestamptz;
UPDATE keygate.key_versions SET original_not_after=not_after;
ALTER TABLE keygate.key_versions ALTER COLUMN original_not_after SET NOT NULL;
ALTER TABLE keygate.key_versions ADD COLUMN original_expiry_known boolean NOT NULL DEFAULT false;
ALTER TABLE keygate.key_versions ADD COLUMN retire_at timestamptz;
CREATE TABLE keygate.rotation_tasks (
 environment text NOT NULL, client_id text NOT NULL, issue_id text NOT NULL,
 old_version bigint NOT NULL, new_version bigint NOT NULL,
 state text NOT NULL DEFAULT 'preparing' CHECK(state IN ('preparing','overlap','completed','failed')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz,
 PRIMARY KEY(environment,issue_id),
 FOREIGN KEY(environment,client_id,new_version) REFERENCES keygate.key_versions(environment,client_id,version)
);
CREATE UNIQUE INDEX one_open_rotation ON keygate.rotation_tasks(environment,client_id) WHERE state IN ('preparing','overlap');
