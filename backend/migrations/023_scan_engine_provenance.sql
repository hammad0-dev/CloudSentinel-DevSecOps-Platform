-- ML engine plumbing: which engine produced a scan, and the tool provenance it ran with
-- (model name, version, SHA-256 of the model file). NULL engine = legacy default (sonar / zap).
ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS scan_engine VARCHAR(20);
ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS tool_provenance JSONB;
ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS scan_engine VARCHAR(20);
ALTER TABLE dast_scans ADD COLUMN IF NOT EXISTS tool_provenance JSONB;
