-- Module 6 FE-2: container-image vulnerability scan history.
-- Additive and idempotent. Apply after migration 007.

CREATE TABLE IF NOT EXISTS image_scans (
  id SERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  pipeline_execution_id INTEGER,
  deployment_attempt INTEGER,
  image_tag VARCHAR(300) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'RUNNING',
  total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
  critical INTEGER NOT NULL DEFAULT 0,
  high INTEGER NOT NULL DEFAULT 0,
  medium INTEGER NOT NULL DEFAULT 0,
  low INTEGER NOT NULL DEFAULT 0,
  unknown INTEGER NOT NULL DEFAULT 0,
  failure_reason TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT image_scans_status_check CHECK (status IN ('RUNNING', 'COMPLETED', 'BLOCKED', 'FAILED')),
  CONSTRAINT image_scans_attempt_check CHECK (deployment_attempt IS NULL OR deployment_attempt > 0),
  CONSTRAINT image_scans_id_project_id_key UNIQUE (id, project_id)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'image_scans'::regclass AND conname = 'image_scans_pipeline_execution_project_fkey'
  ) THEN
    ALTER TABLE image_scans
      ADD CONSTRAINT image_scans_pipeline_execution_project_fkey
      FOREIGN KEY (pipeline_execution_id, project_id)
      REFERENCES pipeline_executions (id, project_id)
      ON DELETE SET NULL (pipeline_execution_id);
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'image_scans'::regclass AND conname = 'image_scans_id_project_id_key'
  ) THEN
    ALTER TABLE image_scans
      ADD CONSTRAINT image_scans_id_project_id_key UNIQUE (id, project_id);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS image_scans_project_started_idx ON image_scans (project_id, started_at DESC);
CREATE INDEX IF NOT EXISTS image_scans_pipeline_execution_idx ON image_scans (pipeline_execution_id);

CREATE TABLE IF NOT EXISTS image_vulnerabilities (
  id SERIAL PRIMARY KEY,
  image_scan_id INTEGER NOT NULL,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  vulnerability_id VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  package_name TEXT NOT NULL,
  installed_version TEXT,
  fixed_version TEXT,
  package_type VARCHAR(100),
  title TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT image_vulnerabilities_image_scan_project_fkey
    FOREIGN KEY (image_scan_id, project_id)
    REFERENCES image_scans (id, project_id)
    ON DELETE CASCADE
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'image_vulnerabilities'::regclass AND conname = 'image_vulnerabilities_image_scan_project_fkey'
  ) THEN
    ALTER TABLE image_vulnerabilities
      ADD CONSTRAINT image_vulnerabilities_image_scan_project_fkey
      FOREIGN KEY (image_scan_id, project_id)
      REFERENCES image_scans (id, project_id)
      ON DELETE CASCADE;
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'image_vulnerabilities'::regclass AND conname = 'image_vulnerabilities_image_scan_id_fkey'
  ) THEN
    ALTER TABLE image_vulnerabilities
      DROP CONSTRAINT image_vulnerabilities_image_scan_id_fkey;
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS image_vulnerabilities_scan_idx ON image_vulnerabilities (image_scan_id);
CREATE INDEX IF NOT EXISTS image_vulnerabilities_project_severity_idx ON image_vulnerabilities (project_id, severity);
