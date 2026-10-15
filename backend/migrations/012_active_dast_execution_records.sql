-- Source-only migration; not applied by this task.
CREATE UNIQUE INDEX IF NOT EXISTS pipeline_execution_project_identity ON pipeline_executions(id,project_id);
CREATE TABLE IF NOT EXISTS active_dast_executions (
  id BIGSERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id),
  pipeline_execution_id INTEGER NOT NULL REFERENCES pipeline_executions(id),
  status TEXT NOT NULL CHECK (status IN ('DISABLED','BLOCKED','FAILED','TIMED_OUT','CANCELLED','CLEANUP_FAILED','COMPLETED_WITH_FINDINGS','COMPLETED_NO_FINDINGS')),
  duration_ms INTEGER NOT NULL,
  result JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id,pipeline_execution_id),
  FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id)
);
