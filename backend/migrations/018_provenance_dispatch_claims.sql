-- Prepared only. Migration 017 is already applied; never modify/reapply it.
BEGIN;
CREATE TABLE provenance_dispatch_claims (
 pipeline_execution_id INTEGER PRIMARY KEY REFERENCES pipeline_source_revisions(pipeline_execution_id),
 project_id INTEGER NOT NULL REFERENCES projects(id),
 source_sha256 TEXT NOT NULL CHECK(source_sha256 ~ '^[a-f0-9]{64}$'),
 claim_token UUID NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('claimed','started','finished','blocked')),
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 3),
 lease_until TIMESTAMPTZ NOT NULL,
 started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, reason TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id),
 CHECK(state NOT IN ('started','finished') OR started_at IS NOT NULL),
 CHECK(state<>'finished' OR completed_at IS NOT NULL)
);
CREATE INDEX provenance_dispatch_claims_lease_idx ON provenance_dispatch_claims(state,lease_until);
COMMIT;
