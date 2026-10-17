-- Source-only preparation. Do not apply without separate authorization.
CREATE UNIQUE INDEX IF NOT EXISTS dast_scan_execution_project_identity ON dast_scans(id,project_id,pipeline_execution_id);
CREATE TABLE active_dast_commissioning_phases (
  project_id INTEGER NOT NULL REFERENCES projects(id) CHECK (project_id <> 17),
  pipeline_execution_id INTEGER NOT NULL,
  operator_id INTEGER NOT NULL REFERENCES users(id),
  phase TEXT NOT NULL CHECK (phase IN ('PASSIVE_SETUP','AWAITING_ACTIVE_AUTHORIZATION','ACTIVE_COMMISSIONING','COMPLETED','FAILED','EXPIRED','INVALIDATED','CLEANUP_FAILED')),
  target_id UUID REFERENCES active_dast_targets(id),
  fixture_container_id CHAR(64),
  baseline_scan_id INTEGER REFERENCES dast_scans(id),
  baseline_sha256 CHAR(64),
  runtime_retained BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (project_id,pipeline_execution_id),
  FOREIGN KEY (pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id),
  FOREIGN KEY (target_id,project_id,pipeline_execution_id) REFERENCES active_dast_targets(id,project_id,pipeline_execution_id),
  FOREIGN KEY (baseline_scan_id,project_id,pipeline_execution_id) REFERENCES dast_scans(id,project_id,pipeline_execution_id),
  CHECK (fixture_container_id IS NULL OR fixture_container_id ~ '^[a-f0-9]{64}$'),
  CHECK (baseline_sha256 IS NULL OR baseline_sha256 ~ '^[a-f0-9]{64}$'),
  CHECK (phase NOT IN ('AWAITING_ACTIVE_AUTHORIZATION','ACTIVE_COMMISSIONING') OR
    (target_id IS NOT NULL AND fixture_container_id IS NOT NULL AND baseline_scan_id IS NOT NULL AND baseline_sha256 IS NOT NULL AND runtime_retained))
);
