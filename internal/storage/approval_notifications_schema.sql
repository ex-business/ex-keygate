ALTER TABLE keygate.control_requests ADD COLUMN withdrawn_by text NOT NULL DEFAULT '', ADD COLUMN withdrawal_reason text NOT NULL DEFAULT '', ADD COLUMN withdrawn_at timestamptz, ADD COLUMN notice_terminal boolean NOT NULL DEFAULT false, ADD COLUMN notice_next_scan timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE TABLE keygate.approval_notifications (
 environment text NOT NULL, id text NOT NULL CHECK(length(id)=64), request_id text NOT NULL, recipient_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('approval_turn','approval_ready','approval_rejected','approval_withdrawn','approval_executed','approval_due','approval_expired','approval_invalidated')),
 request_digest text NOT NULL CHECK(length(request_digest)=64), expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), read_at timestamptz,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sending','sent','obsolete','failed')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5), next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(), lease_until timestamptz,
 PRIMARY KEY(environment,id), UNIQUE(environment,request_id,recipient_id,kind),
 FOREIGN KEY(environment,request_id) REFERENCES keygate.control_requests(environment,request_id),
 FOREIGN KEY(environment,recipient_id) REFERENCES keygate.principals(environment,principal_id)
);
CREATE INDEX approval_notice_inbox ON keygate.approval_notifications(environment,recipient_id,created_at DESC,id);
CREATE INDEX approval_notice_due ON keygate.approval_notifications(environment,next_attempt) WHERE state IN ('pending','sending');
CREATE INDEX control_notice_scan ON keygate.control_requests(environment,notice_next_scan) WHERE NOT notice_terminal;

-- 升级只接续仍有效的进行中申请，不补发已经结束的历史通知。
UPDATE keygate.control_requests SET notice_terminal=true WHERE executed OR decision IN ('rejected','cancelled') OR expires_at<=clock_timestamp();
