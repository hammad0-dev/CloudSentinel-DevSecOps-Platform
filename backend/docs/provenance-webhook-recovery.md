# Provenance dispatch recovery — source implementation, not live activation

## Confirmed gap

The original provenance route committed TRIGGERED execution/source/receipt, sent 202, then invoked runPipeline only for a new delivery. A crash between commit and invocation stranded the execution. Duplicate deliveries only acknowledged it. Existing server startup cleanup fails stale scan rows; it does not reconcile TRIGGERED pipelines.

## Implemented boundary

Migration 018 (prepared, not applied) adds `provenance_dispatch_claims`; applied migration 017 is unchanged. The source revision and receipt remain the durable queue. No historical records are backfilled. Only signed-webhook-bound, TRIGGERED executions with an immutable source and receipt can be selected. Completed, failed, RUNNING and already-started records are never selected for rerun.

The route requires a ready recovery dispatcher before registering provenance work. New AND duplicate deliveries wake recovery with the authenticated project/repository/branch/commit tuple. Wakes are hints, not the queue; busy workers or process loss cannot erase committed work. Startup and a 15-second periodic poll recover missed hints. Fresh entries are prioritized over expired entries. One dispatch runs at a time per process, with database project session advisory locks and execution row locks preventing concurrent same-project pipelines across instances.

Claims have 30-second pre-start leases, at most three acquisition attempts, and a 900-second source-admission recovery window (all are finite; constructor/test overrides are bounded). A connection/process crash before start is recoverable after lease expiry. Invalid owner/repository/source, expired static approval, changed policy or exhausted recovery becomes a blocked claim without rewriting historical execution outcomes. A wrong replay hint does not poison the legitimate queue entry.

The orchestrator independently validates the claim token, lease, source fingerprint, current owner/repository, branch/commit, flags and current static approval, then atomically changes TRIGGERED to RUNNING and the claim to started before any stages. A naked runPipeline call cannot bypass this fence in provenance mode. A checked-out claim connection is retained across dispatch; loss prevents a not-yet-started claim from admission. Client/pool errors are sanitized.

**Exactly-once external execution limitation:** a crash after this start fence, even before the first native scan, is uncertain. It is NEVER automatically restarted. Such RUNNING/started cases require authenticated operator investigation and ownership-safe cleanup/reconciliation. This deliberately avoids duplicate scans; resuming native stages would require a separate per-stage idempotency/reconciliation design. Finishing a dispatch does not claim pipeline or AWS success. NO AWS deployment-outbox worker is registered.

## Authorization and evidence

A source admitted from a signature-verified repository default-branch push with null profile/policy is valid for ordinary CI evidence collection. This does not approve deployment. No static artifact/attestations are invented or upgraded later: stageProvenance creates static artifact bindings only for the originally admitted static profile and exact approved policy. Eligibility still requires the approved deployment policy, exact commit/artifact bindings and genuine stage evidence. A later policy cannot silently upgrade a previously ordinary commit.

Static recovery requires the exact still-valid deployment policy and matching project/owner/repository ID/branch. Unknown profiles and malformed Git refs fail closed. Peers recheck immutable fingerprint before starting; actual scanners still fetch/detach/verify the exact commit. Current branch HEAD is never substituted. GitHub HMAC checks remain before registration. Ordinary branch authority is the signed repository's captured default branch, not an invented static deployment approval.

## Activation checklist — separate authorization required

1. Backup/preflight/isolated-restore and separately authorize live migration 018. Never reapply or edit applied 017. Application role needs SELECT/INSERT/UPDATE on claims plus existing source/execution/project permissions. Keep all feature flags off during migration.
2. Review existing source-bound TRIGGERED rows and age before enabling. A restart with both flags enabled WILL start eligible queued CI pipelines. Do not enable merely to probe readiness. Started/uncertain rows must be investigated, not reset to TRIGGERED.
3. Configure BOTH `PIPELINE_PROVENANCE_ENABLED=true` and `PIPELINE_PROVENANCE_RECOVERY_ENABLED=true` only for an authorized pipeline activation. The pool needs at least two connections (one is held per active dispatcher), shared PostgreSQL and private execution-isolated artifact storage. Do not mix old/unfenced backend instances with provenance dispatchers for the same projects. Multi-instance artifact storage/namespace coordination must be validated before multi-instance activation; DB claims alone do not make local files shared.
4. Approve a private deployment policy only if static artifacts/eligibility are intended. Without one, only default-branch source-bound ordinary evidence is allowed; deployment remains blocked. Confirm installed tools, Sonar analysis-revision compatibility, pinned baseline ZAP digest, storage permissions, and current owner/repository configuration. Projects 13 and existing infrastructure remain untouched by this implementation.
5. A separately authorized backend reload is required to load the new source. No restart was performed here. The server creates no recovery timer and makes no recovery queries when flags are off. If provenance is on but recovery/table readiness is missing, the webhook returns 503 before creating an execution.
6. Keep `INFRA_REAL_PLAN_ENABLED=false`, `INFRA_REMOTE_PLAN_AUTHORIZED=false`, apply disabled, AWS deployment consumer absent and `DAST_ACTIVE_ENABLED=false`. Resolve the separately identified immutable-evidence/project-deletion UX/retention issue before broad activation; do not add destructive cascades.

## Tests and operational inspection

Unit tests cover malformed pushes, tuple mismatch, ordinary versus approved-static scope, disabled readiness, expiry/exhaustion, duplicate webhook wakes, signature rejection and fence ordering. The isolated PostgreSQL script now applies 017 + 018 only to its private synthetic cluster, terminates an actual claim backend before start, recovers from fresh dispatcher instances, races concurrent dispatchers, and verifies a started execution is never retried. Its runner is a TEST-ONLY callback, not the real orchestrator: no native scanner, pipeline, AWS call or Terraform command is executed.

Read-only operator inspection after authorized migration:

```sql
SELECT e.id,e.project_id,e.status,q.state,q.attempts,q.lease_until,q.started_at,q.reason
FROM pipeline_executions e
JOIN pipeline_source_revisions s ON s.pipeline_execution_id=e.id
LEFT JOIN provenance_dispatch_claims q ON q.pipeline_execution_id=e.id
WHERE e.status IN ('TRIGGERED','RUNNING')
ORDER BY e.id;
```

Do not expose claim tokens. Missing migration/readiness errors are sanitized. No automatic reset of failed/blocked/started historical executions is implemented.
