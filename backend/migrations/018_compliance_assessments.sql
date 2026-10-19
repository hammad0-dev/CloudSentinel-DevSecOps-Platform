-- FE-3: additive. 017 and existing scanner tables must already exist.
-- No historical ownership, PASS or applicability is inferred.
ALTER TABLE iac_scans ADD COLUMN IF NOT EXISTS configuration_evidence JSONB;
CREATE TABLE IF NOT EXISTS governance_configuration_targets (
 id BIGSERIAL PRIMARY KEY,
 governance_scan_id BIGINT NOT NULL REFERENCES governance_scans(id) ON DELETE CASCADE,
 resource TEXT NOT NULL,
 technology TEXT NOT NULL,
 capture_complete BOOLEAN NOT NULL,
 UNIQUE(governance_scan_id,resource)
);
CREATE TABLE IF NOT EXISTS governance_control_assessments (
 id BIGSERIAL PRIMARY KEY,
 target_id BIGINT NOT NULL REFERENCES governance_configuration_targets(id) ON DELETE CASCADE,
 benchmark_id TEXT NOT NULL,
 benchmark_version TEXT NOT NULL,
 control_id TEXT NOT NULL,
 check_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('PASS','FAIL','NOT_ASSESSED','NOT_APPLICABLE','ERROR')),
 evidence JSONB NOT NULL,
 finding_id BIGINT REFERENCES governance_findings(id) ON DELETE SET NULL,
 UNIQUE(target_id,benchmark_id,benchmark_version,control_id,check_id)
);
CREATE INDEX IF NOT EXISTS governance_assessment_control_idx ON governance_control_assessments(benchmark_id,control_id,target_id);
CREATE INDEX IF NOT EXISTS governance_target_scan_idx ON governance_configuration_targets(governance_scan_id);
