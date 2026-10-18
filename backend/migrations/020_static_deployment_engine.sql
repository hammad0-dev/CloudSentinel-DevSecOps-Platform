-- Prepared only: separately authorize live migration after isolated restore rehearsal.
BEGIN;
CREATE TABLE static_deployment_jobs (
 id BIGSERIAL PRIMARY KEY,
 outbox_id BIGINT NOT NULL UNIQUE REFERENCES deployment_outbox(id),
 project_id INTEGER NOT NULL REFERENCES projects(id),
 pipeline_execution_id INTEGER NOT NULL,
 owner_id INTEGER NOT NULL REFERENCES users(id),
 status TEXT NOT NULL CHECK(status IN ('PLANNING','AWAITING_APPROVAL','APPLYING','PROVISIONED','PUBLISHING','VERIFYING','DEPLOYED','FAILED','NEEDS_OPERATOR_REVIEW')),
 metadata JSONB NOT NULL DEFAULT '{}',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id)
);
CREATE UNIQUE INDEX static_deployment_project_busy ON static_deployment_jobs(project_id)
 WHERE status IN ('PLANNING','AWAITING_APPROVAL','APPLYING','PROVISIONED','PUBLISHING','VERIFYING','NEEDS_OPERATOR_REVIEW');
CREATE TABLE static_deployment_approvals (
 job_id BIGINT PRIMARY KEY REFERENCES static_deployment_jobs(id),
 approved_by INTEGER NOT NULL REFERENCES users(id),
 plan_sha256 TEXT NOT NULL CHECK(plan_sha256 ~ '^[a-f0-9]{64}$'),
 expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE static_deployment_audit (
 id BIGSERIAL PRIMARY KEY,job_id BIGINT NOT NULL REFERENCES static_deployment_jobs(id),
 status TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMIT;
