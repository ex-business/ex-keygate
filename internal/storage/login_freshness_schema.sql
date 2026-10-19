-- 管理登录以权威数据库记录的开始时间约束重新认证，不信任浏览器提供的时间。
ALTER TABLE keygate.login_states ADD COLUMN started_at timestamptz NOT NULL DEFAULT clock_timestamp();
