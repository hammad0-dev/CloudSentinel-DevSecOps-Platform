# Active DAST readiness after diagnostic closure

The genuine runtime evidence remains under `/tmp/cs-zap-capability-2aspu6vu`.
Its original result is FAIL/1 because of two diagnostic assertion defects. Neither
that result nor its sanitized report is rewritten. A new fixture preserves the
sanitized actual responses; corrected offline replay passes without any new
daemon, container, request or scan. UI override-form discovery is explicitly
separate from verified production cancellation/status behavior.

## Prerequisites

| Area | Established evidence | Remaining requirement |
|---|---|---|
| ZAP initialization | 2.17.0; seven selected add-ons and required SQLi/XSS rules; writable profile/preferences; sufficient home; valid default policy; loopback-only IPv4/IPv6 listeners | Preserve the exact verified replacement artifact and startup restrictions |
| Policy/authentication | Exact seven-rule LOW policy; all other rules disabled; valid-key success; missing/wrong-key rejection with logs | No broad fallback or unapproved origin |
| Limits | Actual 2 requests/sec HOST rule and thread/host limits of one accepted and read back | Genuine rate/concurrency enforcement, including spider traffic |
| Reporting | Empty traditional-json report accepted by `dastBaselineScanner.extractFindings` | Real findings export, normalization and persistence after an authorized job |
| Status/cancellation | Empty scan listing and actual UI parameter descriptions | Real completion, cancellation, timeout and cleanup behavior |
| Automation | Correct generated YAML matches bundled 0.60.0 schemas, including supported spider duration/thread settings | Actual job initialization/execution behavior; no job has run |
| Fixture source | Existing Python/SQLite fixture; synthetic data; deterministic SQLi/XSS; constant health; handlers need no outbound network; per-request DB cleanup | Approved immutable Python base, image construction and native health/endpoint/security validation |
| Containment | C1.9B previously passed all 11 genuine cases | Validate actual ZAP and Python-fixture delivery/memberships, exact origin/IP/paths, namespace evidence, redirect/default-deny behavior and cleanup |
| Schema | 012 adds execution/status records; 013 depends on 012 and adds operators/targets/grants/audit with project/execution foreign keys | Migrations remain pending per supplied state; no live schema query/application occurred in this task |
| Authorization | Authenticated grant route checks owner/operator; expiration, execution binding, atomic single consumption, audit and Project 17 exclusion exist | Separately approved operator/target enrollment, valid deployment execution and a non-17 exact disposable target |

## Source wiring that still blocks the first scan

`orchestrator.js` invokes the optional Active stage after existing Module 2
stages. Its disabled default is unchanged. `module2ActiveDast.execute()` requires
the runtime catalog, a consumed database grant, successful execution-linked
deployment and a registered live lifecycle. No generic executor can satisfy it.

`SecureGatewayLifecycle` already accepts an injectable fixture service, but its
default `dastFixture.js` provisions Nginx. That implementation is not the Python
SQLite fixture. The Python image must be delivered through that existing owned
interface before it can satisfy `ActiveZapRuntime.verifyFixture()`; do not create
another application or pipeline.

Inspection found the `activeRuntimeRegistry.register()` implementation but no
production caller, and target-table reads/schema but no production target
enrollment writer. Those trusted bootstrap paths must be completed and tested
before execution-bound grants can bind genuine Python fixture/network identities.
This review does not insert target rows or register fabricated evidence.

The current runtime catalog still has `zap.capabilities: null`, `fixture: null`,
and `containmentAdapterValidated: false`. It points to the original pinned ZAP
base, while the verified replacement archive's imported image identity is
`sha256:c6b328f0dd03c127670d3b6802e74c89c1350addfd44abbfd4e90c36e5894550`.
Its archive SHA-256 is recorded in `zap-diagnostic-contracts.json`. Future artifact
registration must validate the actual replacement identity/provenance against
the production adapter's immutable-reference checks; do not invent a registry
RepoDigest for a locally imported image. Non-scanning evidence does not satisfy
the strict job completion, timeout, cancellation and containment capability gate.

## Smallest next artifact operation

Read-only local image inventory contains no approved standalone Python base.
No Python base digest/version/architecture is claimed verified. Existing
application, ZAP and Minikube images are not approved substitute bases.

Separately approve obtaining one immutable official Python Linux/amd64 base, or
supplying/importing its independently verified local archive. Then perform one
network-disabled capability inspection without scanning or fixture deployment.
Verify Python/SQLite versions, required standard-library modules, numeric UID/GID
10001 execution and bounded `/tmp` behavior. Acquisition/import and container
execution are not authorized by this source-only task.

Only after that evidence should the existing fixture's build instructions be
finalized for a validated fully offline construction method. Image construction,
health/endpoint testing, lifecycle bootstrap work, schema/enrollment changes and
the first contained Active test each remain separately scoped work. No extra ZAP
runtime cycle is needed merely to correct these two already captured assertions.

Frontend files and report schemas were not changed by diagnostic closure, so no
frontend test/build is necessary for this patch. Backend and fixture tests cover
the changed code. `DAST_ACTIVE_ENABLED=false` and the production gate are preserved.
