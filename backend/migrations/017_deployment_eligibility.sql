-- Prepare only: apply separately after backup and isolated verification.
BEGIN;
CREATE TABLE pipeline_source_revisions (
 pipeline_execution_id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
 owner_id INTEGER NOT NULL REFERENCES users(id), repository_id BIGINT NOT NULL CHECK(repository_id>0),
 repository_identity TEXT NOT NULL, branch TEXT NOT NULL,
 commit_sha TEXT NOT NULL CHECK(commit_sha ~ '^[a-f0-9]{40}$'),
 policy_digest TEXT, profile TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(project_id,repository_id,branch,commit_sha),
 FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id)
);
CREATE TABLE github_delivery_receipts (
 delivery_id UUID PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
 payload_sha256 TEXT NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 pipeline_execution_id INTEGER NOT NULL REFERENCES pipeline_source_revisions(pipeline_execution_id),
 received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE deployment_stage_attestations (
 pipeline_execution_id INTEGER NOT NULL, project_id INTEGER NOT NULL REFERENCES projects(id),
 stage TEXT NOT NULL CHECK(stage IN ('SAST','Dependency','IaC','Deploy','DAST')),
 record_id INTEGER NOT NULL, commit_sha TEXT NOT NULL CHECK(commit_sha ~ '^[a-f0-9]{40}$'),
 artifact_sha256 TEXT NOT NULL CHECK(artifact_sha256 ~ '^[a-f0-9]{64}$'),
 snapshot JSONB NOT NULL, fingerprint TEXT NOT NULL CHECK(fingerprint ~ '^[a-f0-9]{64}$'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(pipeline_execution_id,stage,record_id),
 FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id)
);
CREATE TABLE deployment_revision_bindings (
 pipeline_execution_id INTEGER PRIMARY KEY REFERENCES pipeline_source_revisions(pipeline_execution_id),
 project_id INTEGER NOT NULL REFERENCES projects(id), owner_id INTEGER NOT NULL REFERENCES users(id),
 repository_id BIGINT NOT NULL CHECK(repository_id>0), repository_identity TEXT NOT NULL,
 branch TEXT NOT NULL, commit_sha TEXT NOT NULL CHECK(commit_sha ~ '^[a-f0-9]{40}$'),
 profile TEXT NOT NULL CHECK(profile='STATIC_HTML'), artifact_sha256 TEXT NOT NULL CHECK(artifact_sha256 ~ '^[a-f0-9]{64}$'),
 policy_digest TEXT NOT NULL CHECK(policy_digest ~ '^[a-f0-9]{64}$'),
 evidence JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id)
);
CREATE TABLE deployment_eligibility (
 id BIGSERIAL PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
 pipeline_execution_id INTEGER NOT NULL REFERENCES pipeline_executions(id), environment TEXT NOT NULL CHECK(environment='development'),
 idempotency_key TEXT NOT NULL UNIQUE, decision TEXT NOT NULL CHECK(decision IN ('ELIGIBLE','BLOCKED','PENDING_EVIDENCE','UNSUPPORTED')),
 evidence JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
 FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id)
);
CREATE TABLE deployment_outbox (
 id BIGSERIAL PRIMARY KEY, decision_id BIGINT NOT NULL UNIQUE REFERENCES deployment_eligibility(id),
 idempotency_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','claimed','processed','blocked','failed')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0), claim_token UUID, claim_until TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), processed_at TIMESTAMPTZ,
 CHECK ((status='claimed' AND claim_token IS NOT NULL AND claim_until IS NOT NULL) OR (status<>'claimed' AND claim_token IS NULL AND claim_until IS NULL))
);
-- Immutable revision/evidence and decision records; append a new policy decision instead.
CREATE FUNCTION prevent_deployment_evidence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Deployment evidence is immutable'; END;
$$;
CREATE TRIGGER immutable_deployment_binding BEFORE UPDATE OR DELETE ON deployment_revision_bindings
 FOR EACH ROW EXECUTE FUNCTION prevent_deployment_evidence_mutation();
CREATE TRIGGER immutable_deployment_decision BEFORE UPDATE OR DELETE ON deployment_eligibility
 FOR EACH ROW EXECUTE FUNCTION prevent_deployment_evidence_mutation();
CREATE TRIGGER immutable_pipeline_revision BEFORE UPDATE OR DELETE ON pipeline_source_revisions
 FOR EACH ROW EXECUTE FUNCTION prevent_deployment_evidence_mutation();
CREATE TRIGGER immutable_delivery_receipt BEFORE UPDATE OR DELETE ON github_delivery_receipts
 FOR EACH ROW EXECUTE FUNCTION prevent_deployment_evidence_mutation();
CREATE TRIGGER immutable_stage_attestation BEFORE UPDATE OR DELETE ON deployment_stage_attestations
 FOR EACH ROW EXECUTE FUNCTION prevent_deployment_evidence_mutation();
COMMIT;
