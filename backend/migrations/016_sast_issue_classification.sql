-- Prepared only: historical findings are UNKNOWN, never silently reclassified.
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS issue_type TEXT NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS hotspot_review TEXT NOT NULL DEFAULT 'NOT_APPLICABLE';
ALTER TABLE scan_results ADD CONSTRAINT sast_issue_type_valid CHECK
 (issue_type IN ('UNKNOWN','CODE_SMELL','BUG','VULNERABILITY','SECURITY_HOTSPOT'));
ALTER TABLE scan_results ADD CONSTRAINT sast_hotspot_review_valid CHECK
 ((issue_type='SECURITY_HOTSPOT' AND hotspot_review IN ('TO_REVIEW','SAFE','FIXED')) OR
  (issue_type<>'SECURITY_HOTSPOT' AND hotspot_review='NOT_APPLICABLE'));
