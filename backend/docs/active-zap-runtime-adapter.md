# Active ZAP adapter implementation — offline verification

This source change implements scanner control in activeZapRuntime.js. It reuses
an existing live SecureGatewayLifecycle resource registry rather than launching
an unrelated pipeline or treating historical acceptance JSON as proof.

The adapter verifies the grant-bound fixture and scanner-network IDs, both owned
networks and gateway memberships. It rejects a changed fixture address/image,
public host bindings, ownership changes, and an origin policy lacking the exact
/test/sqli and /test/xss path allowlist. ZAP is created on the owned scanner
network, with pull disabled, read-only root/artifacts, dropped capabilities,
no-new-privileges, PID/memory/CPU limits, IPv6 disabled, numeric host pinning and
no published ports. The actual ZAP namespace undergoes fresh route/interface
validation. Each plan is hashed on host and inside the scanner before execution.

Only the established Automation Framework plans are accepted; the two scoped
jobs execute serially. Proxy endpoint options are constructed from inspected
Squid IPv4. Reports are bounded and parsed; errors, nonzero execution, malformed
reports and interrupted scans fail. An outer cancellation/deadline stops the
owned scanner; finally cleanup re-inspects ownership before container removal.
Mounted artifacts remain if scanner removal fails. Cleanup failure now has its
own CLEANUP_FAILED persisted status in unapplied migration 012.

activeRuntimeRegistry.js permits registration only from a genuine live lifecycle
and Docker adapter whose target identities match the grant. It consumes that
registration once. Module 2 now resolves this adapter after atomic persisted grant
consumption. Generic test executors cannot be selected by production execution.
The Docker command allowlist gained only immutable `image inspect`; pull/build/rm
image operations are rejected. There were no Docker calls during this task.

## Limits and remaining blockers

This is a source-tested adapter, not verified production readiness. The current
artifact catalog still lacks vulnerable-fixture image and ZAP capability evidence,
and remains blocked. The prior authentic ZAP metadata record establishes only
image ID/digest, Linux amd64 and configured user, not installed policy/job support.
No new digest or capability is asserted. All fake catalog identities in tests are
explicit test data, never production configuration.

The adapter requires a live lifecycle that has already provisioned the vulnerable
fixture and installed its exact path-restricted Squid policy. The production
preparation path for that lifecycle is not yet implemented: the default lifecycle
still provisions Nginx health fixtures and the original policy. It cannot be
registered as an Active target, and scanner creation will fail the strict image
and path-policy checks. No endpoint registers mock/historical target evidence.

The pinned ZAP image must be inspected in a separately authorized capability test
for rule IDs 40012/40014/40016/40017 (XSS) and 40018/40019/40020 (SQLi), Automation
Framework syntax, rate/delay behavior (including spider limits), proxy config,
namespace tools and complete scan/job status semantics. Exit zero plus a report
is source-tested but not independently verified as full job completion for that
runtime; explicit job-completion evidence remains required before catalog
activation. The vulnerable-fixture runtime also needs approved immutable build
provenance and compatible commands. No downloads/builds/containers are authorized
by this change. Migrations 012/013, operator enrollment and target registration
remain unapplied.

Grant tests cover role bypass, exact identity, expiry, single-use replay, a mocked
concurrent race and transaction/audit SQL. No real PostgreSQL concurrency or
migration execution was performed. Runtime tests cover image/scope/DNS drift,
namespace checks, interrupted/malformed reports and cleanup failure using mocks.

Production end-to-end readiness is BLOCKED pending these facts and preparation
implementation; prior C1.9B success is never substituted for new scanner evidence.
