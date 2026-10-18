# Historical scan evidence retention

Dependency and IaC detail replacement is scoped to project AND scan ID. SAST replacement is similarly project/scan scoped; baseline DAST already was. Active DAST inserts into new scan IDs. New pipeline attempts create new parent records rather than replacing completed attempts.

Migration 019 is prepared, not applied. It adds eight triggers and two functions without rewriting historical rows or changing migration 017. Completed scan details reject insertion, deletion, update and reassignment. Parent row locks serialize detail writes with completion. Attested parent records reject update/delete. Completed parent deletion is rejected even without an attestation. Parent/project mismatches are rejected independently of existing foreign-key coverage.

Existing project hard-delete explicitly deletes scan details; it will fail and roll back for retained completed evidence. Read-only live catalog inspection confirmed cascading project and scan foreign keys for Dependency/IaC details and composite scan/project cascade foreign keys for SAST/DAST details; the new guards reject removal of completed evidence through cascades too. No automatic historical purge is provided. Any future retention/archive operation needs an independently authorized design preserving attestation verification; do not disable triggers or use CASCADE as a cleanup workaround. Temporary checkout cleanup is unchanged.

stageProvenance.detailRecords uses exact project plus scan ID, ordered by detail ID. deploymentEligibility recomputes detailsDigest and recordDigest for each execution-linked attestation; later scan IDs do not alter those fingerprints. Already deleted historical evidence cannot be restored or backfilled by this change.

Validation includes isolated PostgreSQL migration execution against minimal scan tables, same-project A/B retention, protected duplicate insertion, updates/deletes, cross-project rejection, parent deletion and attested parent changes. This is not a live-schema migration rehearsal; perform a backed-up isolated restore rehearsal before separately authorizing 019.

Activation prerequisites: separately verify/apply 019 and reload source under authorization; configure approved private deployment policy and pinned ZAP digest; use a genuinely new approved commit because execution 39 remains ordinary and immutable. Raw-report retention is a separate remaining limitation. Real Terraform/AWS consumers and Active DAST remain disabled.
