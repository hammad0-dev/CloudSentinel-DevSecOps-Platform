-- Source-only migration. Apply only through the approved migration process.
ALTER TABLE active_dast_commissioning_phases
  ADD COLUMN IF NOT EXISTS overall_deadline TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS active_lease_id UUID,
  ADD COLUMN IF NOT EXISTS active_lease_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS active_lease_consumed_at TIMESTAMPTZ;

UPDATE active_dast_commissioning_phases
SET overall_deadline=expires_at
WHERE overall_deadline IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS active_dast_phase_active_lease_once
  ON active_dast_commissioning_phases(active_lease_id)
  WHERE active_lease_id IS NOT NULL;

ALTER TABLE active_dast_commissioning_phases
  ADD CONSTRAINT active_dast_phase_lease_bounds CHECK (
    active_lease_expires_at IS NULL OR
    (overall_deadline IS NULL OR active_lease_expires_at <= overall_deadline)
  );
