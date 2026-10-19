-- Schema changes belong to an independently authorized migration identity.
CREATE SCHEMA IF NOT EXISTS keygate;
CREATE TABLE IF NOT EXISTS keygate.replay_nonces (
    scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
    nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (scope_hash, nonce_hash)
);
CREATE INDEX IF NOT EXISTS replay_expiry ON keygate.replay_nonces (expires_at);
CREATE TABLE IF NOT EXISTS keygate.root_budgets (
    root_id text PRIMARY KEY CHECK (length(root_id) BETWEEN 1 AND 128),
    used bigint NOT NULL DEFAULT 0 CHECK (used >= 0),
    maximum bigint NOT NULL CHECK (maximum BETWEEN 1 AND 1073741824),
    CHECK (used <= maximum)
);
CREATE TABLE IF NOT EXISTS keygate.audit_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id text NOT NULL UNIQUE,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    target_id text NOT NULL,
    result text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS keygate.approval_requests (
    id text PRIMARY KEY,
    draft bytea NOT NULL CHECK (octet_length(draft) <= 1048576),
    votes bytea NOT NULL CHECK (octet_length(votes) <= 1048576),
    revision bigint NOT NULL CHECK (revision >= 1)
);
