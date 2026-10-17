# Same-execution ZAP container reuse

Status: source/offline verified; warm runtime timing and Active findings remain
UNVERIFIED. No TTL, production readiness gate or ordinary Active enablement changes.

The passive autorun JVM exits normally. Its exact scanner container, writable
home, staged artifacts and helper namespace are retained privately with the
fixture/gateway. The process-local runtime object is registered alongside the
existing target; caller JSON or persisted container IDs alone cannot recreate it.
Expiry, cancellation and staging failure clean the runtime before fixture/network
cleanup. Backend restart still invalidates continuity.

Before reuse, the runtime compares execution/owner, fixture, scanner, gateway,
network, target, immutable image and expiry bindings, inspects live resources,
checks current policy bytes, mount hashes and scanner security, and verifies the
existing helper's live namespace/routes/listeners. Continuation then replaces its
baseline-only helper permission with a fresh grant-bound helper and runs all
containment checks again. Profile/JVM bootstrap files are checked by hash rather
than recreated. The previous daemon must be stopped and passive autorun must have
a genuine zero exit marker before its private logs/PID are rotated. This does not
assume a surviving JVM. A fresh authenticated daemon verifies loaded rules, policy,
listeners and configuration and issues two benign correlated requests before a
fresh one-minute SQLi/XSS-only autorun. Active uses plan/report index 1; passive
uses index 0. Exclusive file creation and per-session invocation state prevent
replay. Existing exact rate rules are read back rather than duplicated; changed
rules fail closed. Seven rules, rate 2/sec and concurrency 1 remain required.

## Timing

The cold path still requires 225 seconds. The retained-scanner path requires
**165 seconds**: 60 startup/revalidation, 60 Active job, 15 reporting and 30
cancellation/cleanup reserve. Work aborts 30 seconds before the earliest execution,
retained-runtime, operator scope, signed continuation or grant deadline. At least
105 seconds must still remain before autorun. These are enforced scheduling caps,
not measured guarantees of completion. Cleanup always runs, even after an overrun.

Historical execution 27 left 173.495 seconds after baseline persistence. Its
126.505 seconds of setup/passive overhead and the older passive diagnostic's
requestor 0s / passive-wait 3s / report 1s are actual retained observations. They
provide no measured bound for a reused Active startup or fresh containment.
Nominal headroom against 165 seconds is only 8.495 seconds, before new issuance,
enrollment and inspection overhead. Feasibility is therefore CONDITIONAL, not PASS.

New monotonic measurements capture namespace/bootstrap, daemon/correlated traffic,
autorun, report/verification, reuse verification and cleanup. Passive measurements
are associated with genuine baseline authorization metadata; Active measurements
are associated with its result. Mock timings are not runtime evidence.

## Next separately authorized runtime operation

Refresh legitimate owner approval, load current source/private scope with one
controlled backend restart, and run one genuine Module 2 PASSIVE_SETUP. Immediately
verify the returned waiting execution and actual remaining lifetime. Only then
issue its official signed continuation, enroll the exact retained fixture, issue
one grant and resume once. Every gate must still pass with at least the required
budget. On insufficient time or any failure, clean owned resources and stop; no
retry, TTL extension or fabricated completion. Keep ordinary Active disabled.
Measure real warm startup/containment/reporting/cleanup before claiming feasibility.

## Files in the warm-path implementation

Services: `activeZapRuntime.js`, `activeRuntimeRegistry.js`,
`activeTargetEnrollment.js`, `commissioningFixtureStage.js`,
`commissioningBudget.js`, `commissioningPhases.js`, `activeDastGrants.js`,
`module2ActiveDast.js`. Scripts: `commissioning-approval.js`,
`zap_commissioning_probe.py`. Tests: `active-zap-runtime.test.js`,
`active-runtime-reuse.test.js`, `commissioning-budget.test.js`,
`zap_commissioning_probe_test.py`. Documentation: this file and
`commissioning-time-budget.md`.
