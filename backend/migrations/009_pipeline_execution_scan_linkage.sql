-- Module 12 Phase 1: link orchestrated scan records to their pipeline execution.
-- Additive and idempotent. Manual scans retain a NULL pipeline_execution_id.
-- Do not backfill historical records.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'pipeline_executions'::regclass
      AND conname = 'pipeline_executions_id_project_id_key'
  ) THEN
    ALTER TABLE pipeline_executions
      ADD CONSTRAINT pipeline_executions_id_project_id_key UNIQUE (id, project_id);
  END IF;
END
$$;

ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS pipeline_execution_id INTEGER;
ALTER TABLE dependency_scans ADD COLUMN IF NOT EXISTS pipeline_execution_id INTEGER;
ALTER TABLE iac_scans ADD COLUMN IF NOT EXISTS pipeline_execution_id INTEGER;
ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS pipeline_execution_id INTEGER;

DO $$
DECLARE
  scan_table TEXT;
  constraint_name TEXT;
BEGIN
  FOREACH scan_table IN ARRAY ARRAY['scan_history', 'dependency_scans', 'iac_scans', 'dast_scans']
  LOOP
    constraint_name := scan_table || '_pipeline_execution_project_fkey';
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = scan_table::regclass AND conname = constraint_name
    ) THEN
      EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (pipeline_execution_id, project_id) REFERENCES pipeline_executions (id, project_id) ON DELETE SET NULL (pipeline_execution_id)',
        scan_table,
        constraint_name
      );
    END IF;
  END LOOP;
END
$$;

DO $$
DECLARE
  scan_table TEXT;
  constraint_name TEXT;
BEGIN
  FOREACH scan_table IN ARRAY ARRAY['scan_history', 'dependency_scans', 'iac_scans', 'dast_scans']
  LOOP
    constraint_name := scan_table || '_pipeline_execution_project_not_null_check';
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = scan_table::regclass AND conname = constraint_name
    ) THEN
      EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I CHECK (pipeline_execution_id IS NULL OR project_id IS NOT NULL)',
        scan_table,
        constraint_name
      );
    END IF;
  END LOOP;
END
$$;

CREATE INDEX IF NOT EXISTS scan_history_pipeline_execution_idx ON scan_history (pipeline_execution_id);
CREATE INDEX IF NOT EXISTS dependency_scans_pipeline_execution_idx ON dependency_scans (pipeline_execution_id);
CREATE INDEX IF NOT EXISTS iac_scans_pipeline_execution_idx ON iac_scans (pipeline_execution_id);
CREATE INDEX IF NOT EXISTS dast_scans_pipeline_execution_idx ON dast_scans (pipeline_execution_id);