-- Issue 07: Pipeline execution to deployment history linkage.
-- Apply once, before deploying application code that writes pipeline_execution_id.
-- Example: psql "$DATABASE_URL" -f backend/migrations/007_pipeline_execution_deployment_history.sql
-- This migration is additive, idempotent, and deliberately does not backfill historical rows.

ALTER TABLE deployment_history
  ADD COLUMN IF NOT EXISTS pipeline_execution_id INTEGER,
  ADD COLUMN IF NOT EXISTS deployment_attempt INTEGER;

-- PostgreSQL requires an exact unique key on the referenced column pair.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'pipeline_executions'::regclass
      AND conname = 'pipeline_executions_id_project_id_key'
  ) THEN
    ALTER TABLE pipeline_executions
      ADD CONSTRAINT pipeline_executions_id_project_id_key
      UNIQUE (id, project_id);
  END IF;
END
$$;

-- Replace the earlier single-column FK, if this migration was partially or
-- previously applied, with project-aware referential integrity.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'deployment_history'::regclass
      AND conname = 'deployment_history_pipeline_execution_id_fkey'
  ) THEN
    ALTER TABLE deployment_history
      DROP CONSTRAINT deployment_history_pipeline_execution_id_fkey;
  END IF;

  ALTER TABLE deployment_history
    ADD CONSTRAINT deployment_history_pipeline_execution_id_fkey
    FOREIGN KEY (pipeline_execution_id, project_id)
    REFERENCES pipeline_executions (id, project_id)
    ON DELETE SET NULL (pipeline_execution_id);
END
$$;

CREATE INDEX IF NOT EXISTS deployment_history_pipeline_execution_id_idx
  ON deployment_history (pipeline_execution_id);
