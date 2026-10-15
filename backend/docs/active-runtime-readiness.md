# Active runtime audit and blockers

Read-only Docker image metadata confirmed:

- ZAP reference: zaproxy/zap-stable@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef
- Image ID: sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef
- Linux amd64, configured user zap, working directory /zap.
- Metadata record: /tmp/cloudsentinel-active-zap-image-metadata.json.

These observations do NOT establish installed add-on versions, scanner rule
availability, Automation Framework job support, or network-command capabilities.
No records verify an immutable image serving the new SQLite/WSGI fixture. Existing
Project 17, NodeGoat and Juice Shop images are not substitutes for that fixture.
The catalog therefore records capabilities and fixture as unknown, and execution
remains BLOCKED. No digest or policy availability has been fabricated.

## Authenticated grant implementation

POST /api/dast/active/:projectId/executions/:executionId/grants uses existing JWT
authentication. Orchestrator tokens are rejected. Authorization is evaluated
against current database operator membership, project ownership and execution
membership, not a caller-supplied role. No operators are enrolled automatically.
The request supplies only a target UUID, not a URL or containment evidence.
The target must already be independently registered/verified by a future runtime
adapter. Grant issuance remains blocked while runtime evidence is unavailable.

Migration 013 defines disabled-by-default operator membership, immutable target
references, per-execution unique grants and append-only-by-application audit rows.
Issuance and consumption audit events commit with their transaction. Rejections
are audited after rollback; audit errors fail issuance. Consumption uses a single
conditional UPDATE RETURNING with expiry, operator, owner, project, execution and
target freshness predicates. Concurrent consumers cannot both claim the grant;
replay fails. Target container/network IDs and SQLi/XSS scope are checked again.
Project 17 is explicitly blocked. No schema or membership changes were applied.

## Production integration state

Module 2 resolves persisted grants only after production runtime readiness. Its
test-only generic runtime contract cannot start a production scanner. The existing
legacy runner is also blocked without the new lifecycle adapter. Migration 012
matches the separate Active execution JSON records and all terminal statuses;
migration 013 must follow it. Both are source-only, not applied.

The actual ZAP/vulnerable-fixture containment adapter cannot be verified or safely
enabled with current records. It remains unimplemented rather than falsely
attesting the Nginx acceptance-client namespace. Required next evidence/work:

1. Approved immutable vulnerable-fixture runtime and source provenance.
2. Pinned ZAP rule/add-on/job and command-capability inspection records.
3. A lifecycle adapter owning the actual ZAP container and fixture; namespace
   membership, route/default-deny, DNS/IP pinning and exact-path enforcement.
4. Transaction-bound fixture registration, authenticated operator enrollment and
   grant issuance after migration approval. No approval endpoint can currently
   issue an executable grant while the runtime gate is blocked.
5. Independently validated scanner proxy configuration, rate/deadline/cancellation
   and ownership cleanup against those images.

Full Active end-to-end readiness is BLOCKED, not established by mock tests or the
prior C1.9B acceptance. No runtime resource creation, image downloads, migrations,
scan execution or infrastructure changes occurred during this audit.
