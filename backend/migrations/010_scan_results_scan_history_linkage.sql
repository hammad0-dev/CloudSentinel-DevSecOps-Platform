-- Module 12: preserve SAST findings per scan. Apply after Migration 009.
-- Additive and idempotent. Existing rows deliberately remain unlinked.

ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS scan_history_id INTEGER;
ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS sast_details_linked BOOLEAN NOT NULL DEFAULT FALSE;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='scan_history'::regclass AND conname='scan_history_id_project_id_key') THEN
    ALTER TABLE scan_history ADD CONSTRAINT scan_history_id_project_id_key UNIQUE (id, project_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='scan_results'::regclass AND conname='scan_results_scan_history_project_fkey') THEN
    ALTER TABLE scan_results ADD CONSTRAINT scan_results_scan_history_project_fkey
      FOREIGN KEY (scan_history_id, project_id) REFERENCES scan_history (id, project_id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='scan_results'::regclass AND conname='scan_results_scan_history_project_not_null_check') THEN
    ALTER TABLE scan_results ADD CONSTRAINT scan_results_scan_history_project_not_null_check
      CHECK (scan_history_id IS NULL OR project_id IS NOT NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='scan_history'::regclass AND conname='scan_history_completed_sast_details_linked_check') THEN
    ALTER TABLE scan_history ADD CONSTRAINT scan_history_completed_sast_details_linked_check
      CHECK (status <> 'COMPLETED' OR sast_details_linked = TRUE) NOT VALID;
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS scan_results_scan_history_idx ON scan_results (scan_history_id);
