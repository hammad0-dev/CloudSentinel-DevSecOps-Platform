-- Module 5 Phase A: preserve DAST findings per scan without guessing legacy metadata.
-- Apply only after Migration 009. Existing rows intentionally retain NULL mode/group/policy/fingerprint values.

ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS scan_mode VARCHAR(20);
ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS scan_group_id UUID;
ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS policy_name VARCHAR(100);
ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS policy_version VARCHAR(100);
ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS target_authorization JSONB;
ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS failure_reason TEXT;

ALTER TABLE dast_findings ADD COLUMN IF NOT EXISTS finding_fingerprint CHAR(64);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'dast_scans'::regclass AND conname = 'dast_scans_id_project_id_key') THEN
    ALTER TABLE dast_scans ADD CONSTRAINT dast_scans_id_project_id_key UNIQUE (id, project_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'dast_scans'::regclass AND conname = 'dast_scans_mode_check') THEN
    ALTER TABLE dast_scans ADD CONSTRAINT dast_scans_mode_check
      CHECK (scan_mode IS NULL OR scan_mode IN ('BASELINE', 'ACTIVE', 'API'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'dast_findings'::regclass AND conname = 'dast_findings_scan_project_not_null_check') THEN
    ALTER TABLE dast_findings ADD CONSTRAINT dast_findings_scan_project_not_null_check
      CHECK (scan_id IS NULL OR project_id IS NOT NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'dast_findings'::regclass AND conname = 'dast_findings_scan_project_fkey') THEN
    ALTER TABLE dast_findings ADD CONSTRAINT dast_findings_scan_project_fkey
      FOREIGN KEY (scan_id, project_id) REFERENCES dast_scans (id, project_id)
      ON DELETE CASCADE NOT VALID;
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS dast_scans_project_execution_group_idx
  ON dast_scans (project_id, pipeline_execution_id, scan_group_id);
CREATE INDEX IF NOT EXISTS dast_scans_project_started_idx
  ON dast_scans (project_id, started_at DESC);
CREATE INDEX IF NOT EXISTS dast_findings_scan_idx ON dast_findings (scan_id);
CREATE UNIQUE INDEX IF NOT EXISTS dast_findings_scan_fingerprint_uidx
  ON dast_findings (scan_id, finding_fingerprint)
  WHERE finding_fingerprint IS NOT NULL;
