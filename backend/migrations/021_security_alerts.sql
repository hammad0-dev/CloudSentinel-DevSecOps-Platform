-- Module 11 FE-3/FE-5: persisted security alerts raised by services/threatDetection.js.
BEGIN;
CREATE TABLE IF NOT EXISTS security_alerts (
 id BIGSERIAL PRIMARY KEY,
 rule TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
 source TEXT NOT NULL CHECK(source IN ('backend','k8s','kyverno')),
 project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
 details JSONB NOT NULL DEFAULT '{}',
 status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 resolved_at TIMESTAMPTZ,
 note TEXT,
 CHECK((status = 'RESOLVED') = (resolved_at IS NOT NULL))
);
-- One active alert per rule/key; repeated detections while active are dropped.
CREATE UNIQUE INDEX IF NOT EXISTS security_alerts_active_key
 ON security_alerts(rule, (details->>'key')) WHERE status <> 'RESOLVED';
CREATE INDEX IF NOT EXISTS security_alerts_created ON security_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS security_alerts_project ON security_alerts(project_id, created_at DESC);
COMMIT;
