CREATE TABLE keygate.recovery_tasks (
 environment text NOT NULL, recovery_id text NOT NULL, client_id text NOT NULL,
 incident_id text NOT NULL, evidence_hash text NOT NULL CHECK(length(evidence_hash)=64),
 issue_id text NOT NULL, key_version bigint NOT NULL, prepared_revision bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('preparing','staged','completed','aborted')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), finished_at timestamptz,
 PRIMARY KEY(environment,recovery_id), UNIQUE(environment,issue_id),
 FOREIGN KEY(environment,client_id,key_version) REFERENCES keygate.key_versions(environment,client_id,version)
);
CREATE UNIQUE INDEX one_open_recovery ON keygate.recovery_tasks(environment,client_id) WHERE state IN ('preparing','staged');
