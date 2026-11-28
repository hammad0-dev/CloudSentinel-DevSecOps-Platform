-- 026: source revision of webhook-triggered executions (Module 12 execution report: branch, commit SHA and message).
-- Additive and idempotent. Existing rows stay NULL (no backfill); the report says "not recorded" for them.
ALTER TABLE pipeline_executions ADD COLUMN IF NOT EXISTS source_branch TEXT;
ALTER TABLE pipeline_executions ADD COLUMN IF NOT EXISTS source_commit TEXT;
ALTER TABLE pipeline_executions ADD COLUMN IF NOT EXISTS source_commit_message TEXT;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'pipeline_executions_source_commit_sha') THEN
    ALTER TABLE pipeline_executions ADD CONSTRAINT pipeline_executions_source_commit_sha
      CHECK (source_commit IS NULL OR source_commit ~ '^[a-f0-9]{40}$');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'pipeline_executions_source_bounds') THEN
    ALTER TABLE pipeline_executions ADD CONSTRAINT pipeline_executions_source_bounds
      CHECK ((source_branch IS NULL OR length(source_branch) <= 200) AND (source_commit_message IS NULL OR length(source_commit_message) <= 500));
  END IF;
END $$;
