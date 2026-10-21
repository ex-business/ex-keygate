CREATE TABLE keygate.system_monitor_samples (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), process_id text NOT NULL,
 node_id text NOT NULL, generation bigint NOT NULL, incarnation bigint NOT NULL, sampled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 auth jsonb NOT NULL, plugins jsonb NOT NULL, PRIMARY KEY(environment,process_id)
);
CREATE INDEX system_monitor_fresh ON keygate.system_monitor_samples(environment,sampled_at);
CREATE TABLE keygate.system_monitor_alerts (
 environment text NOT NULL REFERENCES keygate.security_domains(environment), code text NOT NULL,
 active boolean NOT NULL, count bigint NOT NULL, severity text NOT NULL,
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(), checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,code)
);
CREATE TABLE keygate.system_monitor_events (
 sequence bigserial PRIMARY KEY, environment text NOT NULL REFERENCES keygate.security_domains(environment),
 event_id text NOT NULL, node_id text NOT NULL DEFAULT '', code text NOT NULL, active boolean NOT NULL, count bigint NOT NULL,
 observed_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(environment,event_id)
);
CREATE INDEX system_monitor_history ON keygate.system_monitor_events(environment,sequence DESC);
