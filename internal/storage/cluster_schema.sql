-- 集群只允许一个权威写库；本表不构成数据库主备选举或跨中心共识。
CREATE TABLE keygate.runtime_cluster (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 cluster_id text NOT NULL DEFAULT '',
 configuration_hash text NOT NULL DEFAULT '',
 enabled boolean NOT NULL DEFAULT false,
 generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
 CHECK(NOT enabled OR (length(cluster_id) BETWEEN 1 AND 128 AND configuration_hash ~ '^[0-9a-f]{64}$'))
);
INSERT INTO keygate.runtime_cluster(singleton) VALUES(true);
CREATE TABLE keygate.runtime_nodes (
 node_id text PRIMARY KEY CHECK(length(node_id) BETWEEN 1 AND 128),
 instance_hash bytea NOT NULL CHECK(octet_length(instance_hash)=32),
 cluster_generation bigint NOT NULL CHECK(cluster_generation>0),
 incarnation bigint NOT NULL CHECK(incarnation>0),
 expires_at timestamptz NOT NULL,
 drained boolean NOT NULL DEFAULT false
);
