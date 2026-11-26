-- 025: rotation policy and expiry date per Kubernetes secret (Module 9, SRS FR-20.4/FR-20.6). Additive only.
-- Holds metadata the owner enters; never a secret value. The Secrets Management screen works without this table
-- (policies then read as "unavailable") so applying it is optional until someone sets a policy.
CREATE TABLE IF NOT EXISTS secret_policies (
  id SERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  namespace TEXT NOT NULL CHECK (namespace ~ '^cloudsentinel-p-[1-9][0-9]*$'),
  secret_name TEXT NOT NULL CHECK (length(secret_name) <= 253 AND secret_name ~ '^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$'),
  rotation_days INTEGER CHECK (rotation_days IS NULL OR rotation_days BETWEEN 1 AND 3650),
  expires_at DATE,
  updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (project_id, namespace, secret_name)
);
CREATE INDEX IF NOT EXISTS secret_policies_expiry ON secret_policies (expires_at) WHERE expires_at IS NOT NULL;
