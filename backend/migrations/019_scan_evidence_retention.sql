-- Forward-only preparation; do not apply without explicit migration authorization.
-- Completed scan details are retained. There is no automatic evidence purge.
BEGIN;
CREATE FUNCTION protect_completed_scan_details() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE item jsonb; parent_status text; parent_project integer;
BEGIN
  IF TG_OP = 'UPDATE' AND (to_jsonb(NEW)->>TG_ARGV[1] IS DISTINCT FROM to_jsonb(OLD)->>TG_ARGV[1]
      OR NEW.project_id IS DISTINCT FROM OLD.project_id) THEN
    RAISE EXCEPTION 'SCAN_EVIDENCE_IDENTITY_IMMUTABLE';
  END IF;
  IF TG_OP='DELETE' THEN item:=to_jsonb(OLD); ELSE item:=to_jsonb(NEW); END IF;
  -- Serialize detail mutations with parent completion, including duplicate writers.
  EXECUTE format('SELECT status,project_id FROM %I WHERE id=$1 FOR UPDATE',TG_ARGV[0])
    INTO parent_status,parent_project USING (item->>TG_ARGV[1])::integer;
  IF parent_status IS NULL OR parent_project IS DISTINCT FROM (item->>'project_id')::integer THEN
    RAISE EXCEPTION 'SCAN_EVIDENCE_PARENT_MISMATCH';
  END IF;
  IF parent_status='COMPLETED' THEN RAISE EXCEPTION 'COMPLETED_SCAN_EVIDENCE_IMMUTABLE'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END;
$$;
CREATE FUNCTION protect_attested_scan_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM deployment_stage_attestations WHERE stage=TG_ARGV[0]
      AND record_id=OLD.id AND project_id=OLD.project_id) THEN
    RAISE EXCEPTION 'ATTESTED_SCAN_RECORD_IMMUTABLE';
  END IF;
  IF TG_OP='DELETE' AND OLD.status='COMPLETED' THEN
    RAISE EXCEPTION 'COMPLETED_SCAN_RETENTION_REQUIRED';
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END;
$$;
CREATE TRIGGER retain_sast_details BEFORE INSERT OR UPDATE OR DELETE ON scan_results
 FOR EACH ROW EXECUTE FUNCTION protect_completed_scan_details('scan_history','scan_history_id');
CREATE TRIGGER retain_dependency_details BEFORE INSERT OR UPDATE OR DELETE ON sbom_components
 FOR EACH ROW EXECUTE FUNCTION protect_completed_scan_details('dependency_scans','scan_id');
CREATE TRIGGER retain_iac_details BEFORE INSERT OR UPDATE OR DELETE ON iac_findings
 FOR EACH ROW EXECUTE FUNCTION protect_completed_scan_details('iac_scans','scan_id');
CREATE TRIGGER retain_dast_details BEFORE INSERT OR UPDATE OR DELETE ON dast_findings
 FOR EACH ROW EXECUTE FUNCTION protect_completed_scan_details('dast_scans','scan_id');
CREATE TRIGGER retain_sast_record BEFORE UPDATE OR DELETE ON scan_history
 FOR EACH ROW EXECUTE FUNCTION protect_attested_scan_record('SAST');
CREATE TRIGGER retain_dependency_record BEFORE UPDATE OR DELETE ON dependency_scans
 FOR EACH ROW EXECUTE FUNCTION protect_attested_scan_record('Dependency');
CREATE TRIGGER retain_iac_record BEFORE UPDATE OR DELETE ON iac_scans
 FOR EACH ROW EXECUTE FUNCTION protect_attested_scan_record('IaC');
CREATE TRIGGER retain_dast_record BEFORE UPDATE OR DELETE ON dast_scans
 FOR EACH ROW EXECUTE FUNCTION protect_attested_scan_record('DAST');
COMMIT;
