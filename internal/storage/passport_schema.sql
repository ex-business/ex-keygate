CREATE TABLE keygate.passport_executions (
 environment text NOT NULL,
 request_id text NOT NULL,
 operation_id text NOT NULL UNIQUE,
 digest text NOT NULL CHECK(length(digest)=64),
 endpoint_binding text NOT NULL CHECK(length(endpoint_binding)=64),
 request_hash text NOT NULL CHECK(length(request_hash)=64),
 state text NOT NULL DEFAULT 'unknown' CHECK(state IN ('unknown','succeeded','failed')),
 revision bigint,
 delivery_state text NOT NULL DEFAULT 'pending' CHECK(delivery_state IN ('pending','encrypted','unavailable','not_required')),
 ciphertext bytea,
 oaep_label bytea,
 PRIMARY KEY(environment,request_id),
 FOREIGN KEY(environment,request_id) REFERENCES keygate.control_requests(environment,request_id)
);
