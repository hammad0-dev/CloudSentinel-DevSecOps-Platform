# Active DAST production wiring

This is source integration, not runtime approval. Active DAST remains disabled.
No migration, enrollment, grant or scan is performed by the readiness command.

## One read-only command

```bash
umask 077
DAST_ACTIVE_ENABLED=false node backend/scripts/active-dast-readiness.js
```

For an operator-selected real execution, supply all three identities:

```bash
DAST_ACTIVE_ENABLED=false node backend/scripts/active-dast-readiness.js \
  --project "$PROJECT_ID" --execution "$EXECUTION_ID" --operator "$OPERATOR_ID"
```

No guessed identities or Project 17 are permitted. Missing context is reported
BLOCKED. The CLI checks live schema/ownership constraints, immutable local
ZAP/fixture/Squid/helper images, production capability gates and existing
operator/execution/staging/baseline/target records. It uses SELECT and image
inspection only. It cannot inspect the backend process's live registry from a
separate process and explicitly reports that requirement. Exit 0 means PASS;
BLOCKED exits 1. Redirect reports only into owner-restricted files.

## Evidence registration

The artifact catalog now references the verified replacement ZAP image ID and
its exact configuration/layers, rather than the original base image. Bare local
IDs are validated against the known immutable ZAP configuration; repository
digests are still required for repository references. The verified Python image
and pinned Squid/helper images are unchanged.

`verifiedConfiguration` records observed loaded versions, seven rule IDs,
seven-rule LOW/LOW policy readback, concurrency readback and JSON compatibility.
The historical rate-rule readback applied to **127.0.0.1**, not the disposable
fixture; that scope is recorded explicitly. The 12-case containment evidence is
identified as helper traffic in ZAP's shared namespace. It is not ZAP application
traffic or proof of job/rate/cancellation behavior. Production capabilities and
`containmentAdapterValidated` remain unverified; no readiness flag is promoted.

## Existing Module 2 flow

The existing orchestrator remains the only execution caller. Its sequence is
security stages, deployment, passive DAST, then optional Active DAST. Before any
grant consumption, the backend verifies an enabled database operator owning the
project and RUNNING execution, a successful deployment with a valid staging URL,
and a completed baseline for that same URL/execution. Prerequisites are checked
again after waiting for authorization, and consumption atomically checks owner,
execution, target, expiration and deployment/baseline relationships.
Fresh immutable image, fixture, gateway and policy inspection also occurs before
consumption. Grant scope is compared with the independently enrolled target
snapshot. Pipeline baseline requests resolve the successful staging deployment
for their execution; manual baseline requests retain the owner's configured URL.

With Active explicitly enabled in a separately approved bounded backend context
and all capability gates genuinely satisfied, Module 2 waits at most five minutes
for operator enrollment and a grant. There is no standalone Active scan route.

An existing authenticated owner, already enabled in `active_dast_operators`, uses:

```http
POST /api/dast/active/<projectId>/executions/<executionId>/targets
Authorization: Bearer <existing owner JWT>
Content-Type: application/json

{"fixtureKind":"cloudsentinel-vulnerable-v1"}
```

The server generates the scan identity and disposable `.test:18080` origin;
callers cannot choose an image, origin, address, snapshot or executor. Provisioning
reuses the existing lifecycle and path-restricted Squid policy. Fresh fixture
inspection and execution/operator checks precede the existing transactional
`activeRuntimeRegistry.enroll` call. Target registration stays in the backend
process that runs Module 2; historical diagnostic resources cannot be registered.
Partial provisioning is cleaned. Pending enrollment expires after five minutes;
expiry/cancellation cleanup failures remain visible as CLEANUP_FAILED.

The returned target UUID is then used with the existing grant endpoint:

```http
POST /api/dast/active/<projectId>/executions/<executionId>/grants
Authorization: Bearer <existing owner JWT>
Content-Type: application/json

{"targetId":"<server-enrolled UUID>"}
```

Pipeline-orchestrator JWTs cannot enroll targets or issue grants. No self-service
operator elevation is introduced; enabling an actual operator is a separate
privileged administration action. Grant uniqueness/replay checks and atomic
consumption are unchanged in principle and now include stage prerequisites.

## Production scanner namespace

After consumption, ActiveZapRuntime creates its hardened scanner. Before any ZAP
job, a private, issued-authorization-bound permit identifies that exact scanner
ID, image, network context and readonly work mount. The old bridge client is
removed safely. A newly lifecycle-owned helper joins
`--network container:<immutable scanner ID>` using the existing verified native
CONNECT artifact. Every helper observation rechecks parent/helper ownership,
resource/mount restrictions and matching live `/proc/self/ns/net` values.

The genuine Active fixture observation matrix runs in that namespace. Evidence
must bind both helper and actual scanner IDs; a separate bridge client, diagnostic
token, copied route snapshot or configured address is insufficient. Namespace
identity is rechecked during scanner verification before/after jobs. The evidence
still describes helper-originated requests, never ZAP application requests.
Fresh route/interface observations use the existing BusyBox commands and strict
parser in that shared namespace on each scanner verification, not a copied old
route snapshot. Production preparation uses a private expiring operator scope
for native CONNECT; enabling Active mode alone cannot bypass acceptance controls.
TCP/TCP6/UDP/UDP6 listener tables are re-observed as well; non-loopback listeners
are rejected. These remain structural IPv6 checks, not packet-level tests.

Cleanup removes the helper before the scanner, then the lifecycle's gateway,
fixture, networks and staged artifacts. Lost create responses are recovered only
by reserved name plus immutable image/ownership/namespace checks. Foreign or
ambiguous resources preserve the parent/artifacts and cause cleanup failure.

Findings continue through Module 2's normalization/persistence/reporting path,
with CWE-89 SQLi and CWE-79 XSS, deduplication, separate Active/Passive results,
and explicit BLOCKED/FAILED/TIMED_OUT/CANCELLED/CLEANUP_FAILED statuses.

## Remaining runtime boundary

The temporary ZAP image was removed after the approved diagnostic. Restoring its
verified offline archive needs separate approval. Before production capabilities
can be registered as ready, bounded disposable runtime validation must establish
ZAP application proxy use and scope/redirect behavior, actual request-rate
enforcement, and genuine completion/timeout/cancellation behavior. Normal scan
completion cannot establish deliberate cancellation. No boolean should be set
merely to permit a first scan; the production gate remains closed until genuine
evidence satisfies it. This source task does not authorize that validation or
loading/restarting the backend with the new routes.

## Files in this wiring change

- `backend/config/active-runtime-artifacts.json`
- `backend/routes/dast.js`
- `backend/services/activeRuntimeArtifacts.js`
- `backend/services/activeRuntimeRegistry.js`
- `backend/services/activeZapRuntime.js`
- `backend/services/module2ActiveDast.js`
- `backend/services/activeDastGrants.js`
- `backend/services/dastAcceptanceClient.js`
- `backend/services/dastGateway.js`
- `backend/services/runtimeObservation.js`
- `backend/services/nativeConnectArtifact.js`
- `backend/services/activeDastPrerequisites.js`
- `backend/services/activeTargetEnrollment.js`
- `backend/services/activeScannerBinding.js`
- `backend/services/activeDastReadiness.js`
- `backend/scripts/active-dast-readiness.js`
- `backend/test/active-zap-runtime.test.js`
- `backend/test/active-dast-grants.test.js`
- `backend/test/python-fixture-lifecycle.test.js`
- `backend/test/active-production-wiring.test.js`
- `backend/test/active-scanner-namespace.test.js`
- `backend/docs/active-dast-production-wiring.md`
