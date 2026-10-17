# Historical isolated DAST display

GET /api/dast/diagnostics/:projectId requires the existing authenticated owner
session. Pipeline-orchestrator tokens are denied. A SELECT-only ownership query
precedes lookup in the server-controlled historical-dast-diagnostics.json
catalog. No arbitrary file paths or diagnostic registrations are accepted from
requests. Project 17 receives no Project 11 diagnostic data.

The catalog pins the independently validated manifest and diagnostic-result
hashes. All five bundle artifacts are checked against their pinned manifest
hashes on every read. Files must be regular, private 0600 files in an owned 0700
directory. Symlink files, altered evidence, incomplete files, scope mismatches,
unverified completion and inconsistent reports fail closed. Errors expose no
filesystem paths or native errors. The API returns only safe fields, endpoint
paths without query values, artifact hashes and genuine evidence status.

Verified files were copied from the retained temporary artifacts into the private
local catalog directory under ~/.local/share/cloudsentinel/diagnostics/. They are
not database rows or pipeline evidence. Back up that private directory separately;
loss of it produces unavailable evidence, never fabricated findings. The sanitized
report bytes are retained, together with the original-report SHA-256 attestation;
this does not claim retention or revalidation of unsanitized original bytes.

The Project 11 DAST page renders a separate panel labeled "Historical Isolated
Active DAST Diagnostic — Not Part of Execution #37". Existing pipeline counts,
findings and stage statuses are untouched. Execution 37 belongs to Project 17 and
its unexecuted Active stage continues to display Skipped. No diagnostic findings
are attributed to that website. Evidence is INCOMPLETE and production acceptance
BLOCKED because request attribution/dispatch-rate verification remains incomplete.

Activation needs a separately authorized backend restart and serving the rebuilt
frontend (the Vite dev server normally reloads changed modules automatically).
No migration, rescan, grant or pipeline execution is required.
