-- Module 12: additive, repeatable. Apply after existing scanner migrations.
CREATE TABLE IF NOT EXISTS governance_findings (
 id BIGSERIAL PRIMARY KEY,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 source TEXT NOT NULL,
 fingerprint TEXT NOT NULL,
 identity TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '',
 severity TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN')),
 location TEXT NOT NULL DEFAULT '',
 references_json JSONB NOT NULL DEFAULT '[]',
 remediation TEXT NOT NULL DEFAULT '',
 mappings JSONB NOT NULL DEFAULT '[]',
 classification TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','RESOLVED','ACCEPTED_RISK','FALSE_POSITIVE')),
 first_seen TIMESTAMPTZ NOT NULL,
 last_seen TIMESTAMPTZ NOT NULL,
 UNIQUE(project_id,source,fingerprint)
);
CREATE TABLE IF NOT EXISTS governance_scans (
 id BIGSERIAL PRIMARY KEY,
 project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 source TEXT NOT NULL,
 scan_id TEXT NOT NULL,
 scanned_at TIMESTAMPTZ NOT NULL,
 source_status TEXT NOT NULL,
 details_complete BOOLEAN NOT NULL,
 raw_count INTEGER NOT NULL,
 imported_count INTEGER NOT NULL DEFAULT 0,
 UNIQUE(project_id,source,scan_id)
);
CREATE TABLE IF NOT EXISTS governance_observations (
 id BIGSERIAL PRIMARY KEY,
 finding_id BIGINT NOT NULL REFERENCES governance_findings(id) ON DELETE CASCADE,
 governance_scan_id BIGINT NOT NULL REFERENCES governance_scans(id) ON DELETE CASCADE,
 source_record_id TEXT NOT NULL,
 observed_at TIMESTAMPTZ NOT NULL,
 evidence JSONB NOT NULL,
 UNIQUE(finding_id,governance_scan_id)
);
CREATE TABLE IF NOT EXISTS governance_status_history (
 id BIGSERIAL PRIMARY KEY,
 finding_id BIGINT NOT NULL REFERENCES governance_findings(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id),
 old_status TEXT NOT NULL,
 new_status TEXT NOT NULL,
 reason TEXT NOT NULL,
 changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS governance_findings_project_idx ON governance_findings(project_id,source,severity,status);
CREATE INDEX IF NOT EXISTS governance_observations_time_idx ON governance_observations(finding_id,observed_at DESC);
CREATE INDEX IF NOT EXISTS governance_scans_project_idx ON governance_scans(project_id,source,scanned_at DESC);
