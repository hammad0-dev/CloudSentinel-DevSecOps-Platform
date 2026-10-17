# Execution 28 continuation timing and offline optimization

## Genuine retained evidence

Inputs: `/tmp/cs-p11-active-final-yz42jtwq/workflow.log`, the exclusive-created
API/CLI response files in that directory, `sanitized-summary.json`, and
`database-postflight.json`. Historical results are not rewritten.

| Client-side interval between retained response artifacts | Seconds |
| --- | ---: |
| Passive phase received -> official continuation issuer completed | 0.138410 |
| Issuer completed -> exact fixture target lookup completed | 0.004041 |
| Target lookup completed -> grant issuance completed | 3.071662 |
| Grant issued -> resume accepted | 3.089809 |
| Resume accepted -> terminal result received | 45.272752 |

These intervals use the original file modification timestamps, corroborated by
monotonic workflow events: 154.871s at passive completion, 158.085s at grant
issuance, 161.175s at resume and 206.448s at terminal result. They include local
serialization/file-write and HTTP/CLI overhead; they are not exact server-function
latencies. No per-function server trace was retained. PostgreSQL recorded
44.866s for the blocked continuation INCLUDING cleanup. Its exact pending
verification/cleanup split and the remaining milliseconds at rejection are UNKNOWN.
The grant was unconsumed, cleanup succeeded, and no Active Scan occurred.

Remaining lifetime was 173.761s after the passive phase response and approximately
167.457s after resume. Another fresh verification preceded the 165s admission
check and exhausted the margin. Signing was not the main delay.

Passive runtime measurements were 21.333s namespace/bootstrap, 49.000s daemon and
correlated traffic, 40.314s passive autorun, 2.808s report/verification, 113.454s
total. Autorun includes a fresh JVM startup, not just passive jobs. Actual Active
startup, completion, request-rate enforcement and cleanup bounds remain unverified.

## Changes without caching or skipping fresh evidence

- Retained verification previously ran `preflight()` (including fixture/gateway
  verification) followed by `verify()` (which repeated those same checks).
  It now validates capability/authorization/resource bindings, freshly inspects
  both image identities, and performs ONE full live verification. The same
  execution, lifecycle resource object, fixture/network/scanner/gateway and
  expiry bindings remain mandatory. Each invocation gathers fresh observations.
- Independent image inspections, fixture/network/raw container inspections and
  scanner/raw/network inspections run concurrently. No result is cached between
  issuance, resume, consumption, provision or scan.
- Independent route/interface reads and listener-table reads run in batches.
  Every command still uses the trusted client path and its identity checks. The
  before/after namespace comparison and all route/listener predicates remain.
- Every concurrent batch uses `Promise.allSettled`, inspects every result, and
  drains outstanding reads before propagating failure. Cleanup cannot race an
  unawaited inspection. Mutating operations remain sequential.
- Named monotonic continuation timings now distinguish prerequisites, phase,
  grant lookup, fresh verification, grant consumption, provision and cleanup,
  including failures before scanner provision. Insufficient-time results record
  actual remaining/required milliseconds. Official signing, target lookup, grant
  issuance and resume responses expose bounded numeric durations, never secrets.

Execution-independent capability definitions and archive construction stay outside
continuation. Actual immutable-image inspection is retained fresh: moving that
observation earlier and trusting it later would not establish current availability.
No unverified daemon `runPlan` API replaces the verified autorun mechanism. The
retained container/home avoids recreation/bootstrap, but the JVM still starts
fresh, and authentication, seven rules, policy, namespace/containment and benign
correlation remain required. Neither retaining the container nor API endpoint
presence proves a running or compatible JVM.

## Budget and feasibility

The warm admission requirement remains 165s: 60s startup/revalidation, 60s scan,
15s reporting and 30s cancellation/cleanup reserve. This is an enforced scheduling
cap, NOT a measured guarantee. The measured cold namespace plus daemon/traffic
already used 70.333s, and fresh autorun startup is additional. Warm initialization
can differ, but its savings have not been measured. The 44.866s failed continuation
cannot establish a separate 30s cleanup bound. Thus no smaller safe reserve can
be derived from these observations, and no TTL or margin was reduced.

Source optimization PASS; reliable runtime feasibility remains UNVERIFIED. The
five-minute parent window has not been proven fundamentally impossible, because
no optimized warm Active runtime has run. Do not automatically launch another
pipeline merely because offline tests are faster.

If an explicitly authorized measurement still demonstrates insufficient room,
the smallest bounded design alternative is a one-time phase lease under an
administrator-approved immutable overall execution deadline set BEFORE setup:
for example, setup <=300s, Active continuation <=300s, overall <=600s, with >=45s
reserved for cancellation/draining/cleanup based on the observed failed total.
These are proposed review bounds, not runtime guarantees or implemented changes.
A 240s candidate total (120s startup, 60s scan, 15s reporting, 45s cleanup)
would then leave up to 60s for handoff/revalidation inside the phase lease; actual
measurements must still validate it. The present four-minute signing cap would
also require explicit approval to change to five minutes; it is unchanged here.
Issue the phase lease only after genuine baseline, signed owner permission and
fresh resource/containment verification. Atomically bind target, phase, single-use
grant, private runtime timer and cancellation to the earliest parent/phase expiry;
no repeated renewal, no modification of expired execution 28, no global production
enablement. This would explicitly change authorization lifetime and needs separate
approval and tests before implementation, rather than silently extending current
fixture/grant expiries. If it is not approved, the present five-minute limit stays.

## Files changed

`services/verifiedReads.js`, `services/activeRuntimeArtifacts.js`,
`services/activeZapRuntime.js`, `services/activeScannerBinding.js`,
`services/commissioningBudget.js`, `services/module2ActiveDast.js`,
`services/activeDastGrants.js`, `services/commissioningPhases.js`,
`services/activeTargetEnrollment.js`, `scripts/commissioning-approval.js`,
`test/verified-reads.test.js`, `test/active-zap-runtime.test.js`,
`test/commissioning-budget.test.js`, `test/python-fixture-lifecycle.test.js`,
and this document.
