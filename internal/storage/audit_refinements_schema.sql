ALTER TABLE keygate.audit_exports ADD COLUMN filters jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE keygate.rotation_tasks ADD COLUMN reason text NOT NULL DEFAULT 'legacy_unknown';
