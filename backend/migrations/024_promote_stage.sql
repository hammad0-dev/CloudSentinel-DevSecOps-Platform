-- 024: "Promote to EKS" pipeline stage (Module 8). Additive only; existing rows get promote_target='none'
-- (no promotion, behaviour unchanged). The stage treats a missing column as 'none', so applying this is optional
-- until a project opts in.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS promote_target TEXT NOT NULL DEFAULT 'none';
ALTER TABLE projects ADD COLUMN IF NOT EXISTS promote_approval TEXT NOT NULL DEFAULT 'manual';
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'projects_promote_target_check') THEN
    ALTER TABLE projects ADD CONSTRAINT projects_promote_target_check CHECK (promote_target IN ('none', 'eks'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'projects_promote_approval_check') THEN
    ALTER TABLE projects ADD CONSTRAINT projects_promote_approval_check CHECK (promote_approval IN ('manual', 'auto_after_gates'));
  END IF;
END $$;
-- Stage result (status, reason, plan summary, tag, steps); never contains credentials or secret values.
ALTER TABLE pipeline_executions ADD COLUMN IF NOT EXISTS promote_result JSONB;
