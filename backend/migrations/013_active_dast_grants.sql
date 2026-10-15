-- Source only: requires 012. No live application by this task.
CREATE TABLE IF NOT EXISTS active_dast_operators (
  user_id INTEGER PRIMARY KEY REFERENCES users(id),
  enabled BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS active_dast_targets (
  id UUID PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) CHECK(project_id <> 17),
  pipeline_execution_id INTEGER NOT NULL REFERENCES pipeline_executions(id),
  fixture_container_id CHAR(64) NOT NULL,
  scanner_network_id CHAR(64) NOT NULL,
  authorization JSONB NOT NULL,
  verified_until TIMESTAMPTZ NOT NULL,
  UNIQUE(project_id,pipeline_execution_id),
  UNIQUE(id,project_id,pipeline_execution_id),
  FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id)
);
CREATE TABLE IF NOT EXISTS active_dast_grants (
  id UUID PRIMARY KEY,
  target_id UUID NOT NULL REFERENCES active_dast_targets(id),
  project_id INTEGER NOT NULL REFERENCES projects(id) CHECK(project_id <> 17),
  pipeline_execution_id INTEGER NOT NULL REFERENCES pipeline_executions(id),
  operator_id INTEGER NOT NULL REFERENCES users(id),
  authorization JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  UNIQUE(project_id,pipeline_execution_id),
  FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id),
  FOREIGN KEY(target_id,project_id,pipeline_execution_id) REFERENCES active_dast_targets(id,project_id,pipeline_execution_id)
);
CREATE TABLE IF NOT EXISTS active_dast_audit (
  id BIGSERIAL PRIMARY KEY,
  operator_id INTEGER,
  project_id INTEGER,
  pipeline_execution_id INTEGER,
  event TEXT NOT NULL CHECK(event IN ('ISSUED','REJECTED','CONSUMED')),
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
