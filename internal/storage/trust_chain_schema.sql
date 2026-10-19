-- 应用信任根与存储加密根分离；这里只保存公开根，不保存根私钥。
CREATE TABLE keygate.application_trust_roots (
 environment text PRIMARY KEY REFERENCES keygate.security_domains(environment),
 application_environment text NOT NULL,
 fingerprint text NOT NULL CHECK(length(fingerprint)=64),
 certificate bytea NOT NULL CHECK(octet_length(certificate)<=16384)
);
CREATE TABLE keygate.application_trust_services (
 environment text NOT NULL REFERENCES keygate.application_trust_roots(environment),
 service_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 active_version bigint NOT NULL CHECK(active_version>=0),
 disabled boolean NOT NULL DEFAULT false,
 PRIMARY KEY(environment,service_id)
);
CREATE TABLE keygate.application_trust_certificates (
 environment text NOT NULL,service_id text NOT NULL,version bigint NOT NULL CHECK(version>0),
 fingerprint text NOT NULL CHECK(length(fingerprint)=64),
 certificate bytea NOT NULL CHECK(octet_length(certificate)<=16384),
 state text NOT NULL CHECK(state IN ('active','retired','revoked','disabled')),
 PRIMARY KEY(environment,service_id,version),UNIQUE(environment,fingerprint),
 FOREIGN KEY(environment,service_id) REFERENCES keygate.application_trust_services(environment,service_id)
);
