# Non-scanning ZAP containment diagnostic

## Interface and boundary

`backend/scripts/zap-containment-diagnostic.js` is an operator-only local CLI. It accepts only explicit scope, scan identity, numeric project/execution labels and a TTL of at most 600 seconds. Project 17, arbitrary targets/images, extra CLI options, scanner actions and reused identities are rejected. IDs label a disposable diagnostic; no database execution, enrollment or grant is created.

`DAST_ACTIVE_ENABLED=false` is mandatory. The diagnostic does not call production `provision()`, `scan()`, the Module 2 orchestrator or grant APIs. Production readiness checks remain unchanged; diagnostic lifecycle records are explicitly rejected by the production runtime registry and Active runtime. Results always include `diagnosticOnly:true`, `fullContainment:false`, `containmentReady:false` and `zapApplicationRequests:false`, even when diagnostic checks pass. No catalog is promoted or written.

## Artifacts and resources

`zap-containment-diagnostic.json` records the genuinely inspected replacement ZAP image identity/configuration/layers and the exact offline archive hash. It does not claim local availability. The CLI never imports, builds or pulls images. Future restoration requires separate authorization and exact archive verification:

- Archive SHA-256: `3e3604f70c39e65b2637e179b1fc2835c7165e3ff7cc53636f07c3fb01e125f8`.
- Expected imported ZAP image ID: `sha256:c6b328f0dd03c127670d3b6802e74c89c1350addfd44abbfd4e90c36e5894550`.
- Archive configuration digest (distinct from Docker's image ID): `sha256:ae2d7369cc2a3aac99e3a078c903bbe50fde6433e2cc134706dcdfbbd2a042e0`.
- Python fixture ID: `sha256:7a76c5a6a58a677bdf967ed082660bf3e4d2e87800daa618a4882dfbd2e86ff4`.

Preflight inspects these immutable local identities and the existing pinned Squid/Nginx images; missing or changed artifacts block before provisioning. Repo-digest comparisons remove only the optional tag from a tagged digest reference, preserving repository and complete digest. The native CONNECT artifact retains its audited source/binary hashes and existing private staging/readonly mount controls.

One `SecureGatewayLifecycle` creates its existing isolated internal IPv4 scanner/fixture networks, Python fixture and Active-profile Squid gateway. Its diagnostic-only infrastructure state does not assert READY or run the separate bridge client. The diagnostic then creates one ZAP container and one namespace-sharing Nginx observation helper. No ports, host networking, privileged containers or Docker sockets are used.

Profiles:

| Component | User | Memory | CPU | PIDs | Writable storage |
|---|---|---|---|---|---|
| Python fixture | 10001:10001 | 256 MiB | 1 | 64 | Owned 16 MiB `/tmp` tmpfs |
| Squid diagnostic gateway | operator UID/GID | 256 MiB | 1 | 64 | Existing bounded `/run`, log and spool tmpfs |
| ZAP | 1000:1000 | 1536 MiB | 1 | 128 | 256 MiB home, 256 MiB `/tmp`, 4 MiB Firefox profile tmpfs |
| Shared helper | operator UID/GID (1000 required) | 128 MiB | 0.5 | 64 | No writable host storage; audited native file mount is readonly |

All roots are readonly, capabilities are dropped and no-new-privileges is required. ZAP reuses the established readonly private `/zap/wrk` mount and local hostname mapping. Its inherited port-8080 healthcheck is disabled for this container only; explicit loopback-8090 API/readiness checks replace it. JVM heap is capped at 512 MiB via the verified existing bootstrap. The daemon starts with updates/downloads disabled and a private generated API key. Only version, installed-add-on and scanner-inventory **views** are exposed to the diagnostic code. No scan, spider, quick-scan or Automation Framework job is submitted.

## Genuine namespace evidence

The helper is created with `--network container:<full immutable ZAP ID>`. It receives no independent bridge attachment, hostname override or network sysctls. Every trusted helper command re-inspects helper and parent identities, image, ownership, restrictions and network membership.

The helper's actual `/proc/self/ns/net` symlink is read with BusyBox `readlink`. The ZAP container's same symlink is read with its existing Python standard library. Both must return the identical complete `net:[inode]` value. NetworkMode alone, container names, copied route snapshots and a separate bridge client cannot establish equivalence. Native command errors, empty/malformed values, resource mismatches or inode changes fail closed. Namespace identity is checked again after observations.

The existing strict BusyBox IPv4/IPv6 route and address parsers run in that shared namespace and compare against the independently inspected ZAP NIC/IP/MAC. Existing verbose nc direct-TCP denial still requires explicit network-unreachable evidence plus matching identity/routes; silence, refusal, timeout or exit 1 alone remains inconclusive. The audited native CONNECT executable uses the same socket for getpeername and Squid rejection evidence. TCP/TCP6 and UDP/UDP6 tables must be complete and show only loopback listeners, including the API listener. IPv6 evidence is route/address/listener validation, not a packet-level test.

## Harmless traffic and coverage limits

Production Squid ACLs are unchanged: only the exact fixture origin/IP/18080 and `/test/sqli` or `/test/xss` paths are permitted. `/health` remains denied through the proxy; Docker's fixture-local healthcheck establishes readiness separately.

The helper sends benign GET requests without injection payloads. The normal SQLi response must be exactly the synthetic `demo-one` row; the XSS response must contain only the fixture's default `hello` HTML. Actual curl remote peer/status and fresh gateway/fixture ownership, image, membership and policy evidence must agree. Production's existing read-only fixture/path-policy verifier is reused before and after probes.

The Active matrix also checks unauthorized hostname/path/port, numeric-IP bypass, public TEST-NET, metadata, native CONNECT and direct TCP denial. Rejecting `/redirect/host` and unauthorized destinations establishes path/destination policy restrictions. **The current Python fixture does not emit a genuine cross-origin redirect chain.** The diagnostic does not claim ZAP application proxy behavior, redirect-following behavior, actual scan completion/cancellation, rate enforcement, exploit detection or full Active readiness. Those remain separate runtime prerequisites.

## Cleanup and reporting

Startup evidence is collected before teardown, including a fresh owned-container
state, container exit/OOM status, bounded log classification/excerpt and the last
failed readiness view. A shell wrapper records the detached daemon's actual exit
code separately from the container's long-running sleep process. Missing exit
markers do not imply success. A stopped container, incomplete log capture,
daemon exit, initialization errors and readiness timeout remain blocking. Logs
are read from fixed paths with a 1 MiB limit; oversized logs block readiness.
Only bounded redacted excerpts and fingerprints enter the private report. Capture
failure cannot suppress cleanup or convert the validation result to PASS.

Startup classification now parses actual elapsed-time Log4j levels and Java
Util Logging records, associating stack continuations with their originating
record. INFO/DEBUG rule names such as Application Error Disclosure are data,
not ERROR records. Genuine ERROR/FATAL/SEVERE and concrete filesystem, policy,
preferences or binding failures still block. Unrecognized records are UNVERIFIED.
The retained a2 excerpt replays harmlessly without changing its historical
BLOCKED result; it does not establish complete initialization.

Before helper traffic, readiness also requires observed extension/listener
startup markers, loaded add-ons/seven rule APIs, a parsed nonempty Default Policy
XML file, successful temporary-file writes in the four existing writable runtime
locations, and loopback-only TCP/TCP6/UDP/UDP6 observations with the API listener.
These fixed-path observations use the existing ZAP Python standard library and
introduce no new mounts or executables. Missing positive evidence remains pending
until the bounded initialization timeout; unknown or unsafe listeners fail closed.

The retained `zpd-fast-20261016-a1` report proves the startup-log check failed,
but contains no triggering log bytes. Its exact initialization cause is UNKNOWN.
The saved inspection proves the 256 MiB home tmpfs and readonly `/zap/wrk` were
configured, not that workspace writes caused the error. The daemon uses explicit
`-dir /home/zap/.ZAP`; this diagnostic submits no Automation Framework jobs.
Production plans are read from `/zap/wrk` and exported reports are redirected to
`/tmp` by ActiveZapRuntime. No mount destination or host access is changed here.

If future native evidence establishes a required workspace write, the proposed
alternative is a bounded 64 MiB UID/GID 1000 mode-0700 tmpfs at `/zap/wrk` and a
separate minimal readonly input mount at `/opt/cloudsentinel/diagnostic-input`.
That would require explicit authorization of the changed mount destination and
updated strict inspection tests before execution; it is not implemented or
authorized by this correction. Do not replace the existing approved mount based
only on the generic initialization failure.

Cancellation/expiration stops further helper traffic. SIGINT/SIGTERM initiate bounded cancellation and cleanup; commands are bounded by the existing adapter timeout. Uncertain creates are recovered only under the reserved name and then checked by immutable ID, image, role, scope owner and namespace association. Foreign resources are preserved and cleanup fails.

The helper is removed before ZAP and before its native host artifact; ZAP is removed before lifecycle network teardown. Failure to remove a helper preserves its parent and mounted artifacts. The existing lifecycle cleans fixture, gateway, networks, policy and native staging. Missing or incomplete cleanup prevents successful exit. The empty ZAP mount directory is removed only after inode/device/ownership checks. Diagnostic evidence is intentionally retained in a unique 0700 directory with a 0600 file. Failure reports retain sanitized stage, IDs, namespace/route rules, probe verdicts and bounded TCP diagnostic references; API keys and raw daemon/verbose output are not published.

## Future authorized invocation

First perform a fresh infrastructure/inventory preflight and separately approved exact offline-image restoration if required. Then, only after explicit runtime approval:

```sh
DAST_ACTIVE_ENABLED=false node backend/scripts/zap-containment-diagnostic.js \
  --execute --scope zap-python-containment --scan zpd-20261016-a1 \
  --project 18 --execution 1 --ttl 600
```

The labels above do not enroll project/execution records. Select a fresh unused scan identity for the real operation. Independently compare the original nine containers/four networks, retained fixture/base images and Project 17 UID/readiness/restarts after the attempt. This source implementation and its mocked tests authorize no Docker execution.

## Optional commissioning-response diagnostic

The default remains helper-only. `--commissioning-response` explicitly opts into
exactly two authenticated ZAP `core/action/sendRequest` calls after the complete
namespace containment and listener checks. Requests use the verified fixture
hostname and port 18080, `/test/sqli?id=1` and `/test/xss?q=hello`, plus a generated
correlation nonce. Redirect following is disabled. No arbitrary URL, request,
policy, production session or grant can be supplied. The private one-use permit
is separate from production baseline/Active authorization. The existing generic
API method still rejects action endpoints.

```bash
DAST_ACTIVE_ENABLED=false node backend/scripts/zap-containment-diagnostic.js \
  --execute --scope zap-python-containment --scan cr-p11-20261016-a1 \
  --project 11 --execution 25 --ttl 300 --commissioning-response
```

Run only with separate runtime approval and fresh inventory checks. Numeric IDs
are diagnostic labels, not created database execution/user records. The flag
never runs Module 2, spidering, passive jobs or Active Scan jobs. Even successful
results retain `diagnosticOnly:true`, `fullContainment:false` and
`containmentReady:false`. `zapApplicationRequests:true` reports only the two
verified benign application requests; production readiness is unchanged.

Response validation reuses the production exact request/header/status/Via/body
contract. The two nonce-tagged Squid records must match the independently
inspected ZAP namespace IP. Private response artifacts (0700 directory, 0600
file) contain fingerprints, failed predicates and bounded redacted access logs,
not unrestricted response headers/bodies. Missing evidence or a persistence
failure blocks success; original failures and mandatory cleanup are preserved.
The staged fixed driver is hash/ownership checked and removed after container
teardown. Evidence survives that cleanup.

## Explicit Project 11 Active milestone diagnostic

Disabled by default. This local-only option uses a genuine private User 3 session and SELECT-only Project 11 ownership verification, followed by a permanent exclusive local claim file and private one-use in-process capability. It cannot supply a Module 2 grant or readiness record. No production gate is changed. `--execution` is a historical reference for correlation only; no pipeline execution is created, resumed or rewritten.

After explicit approval for one diagnostic, the supported invocation is:

```sh
DAST_ACTIVE_ENABLED=false node backend/scripts/zap-containment-diagnostic.js \
 --execute --scope zap-python-containment --project 11 --execution 32 \
 --scan UNIQUE-DIAGNOSTIC-ID --ttl 480 --active-diagnostic \
 --session /tmp/cs-p11-owner-qdumw2us/session.json
```

The exact generated fixture-only plan has one seven-rule Active job, no spider, concurrency 1, configured rate 2/sec, maxScanDurationInMins 1 and maxRuleDurationInMins 1. A 60-second outer autorun bound also aborts the attempt. Existing immutable image, fixture, Squid, namespace, route and denial preconditions remain mandatory. Active and passive-autorun options are mutually exclusive.

Sanitized native Automation output and original-report hashes, sanitized JSON/alerts, approved-rule CWE counts and owned identities are captured before teardown in private 0700/0600 evidence bundles. Measured rate enforcement remains UNVERIFIED; the bundle's production acceptance stays BLOCKED. Diagnostic completion cannot promote full containment or Module 2 acceptance. Every invocation requires a fresh permitted identity; the same local scan authorization cannot be claimed twice. A failed attempt is never retried automatically.

### Active diagnostic phase deadlines

The diagnostic-only autorun budget is 90 seconds for JVM/plan initialization,
60 seconds for the Active job, and 30 seconds for report export and evidence
finalization. Admission requires all 180 seconds plus a 30-second cleanup reserve
before the immutable diagnostic expiry. Earlier phase completion does not renew
any deadline. Cleanup still uses the existing finite Docker operation timeouts
and ownership checks; a failed cleanup is reported, never hidden by the reserve.

The observer requires exact `Job activeScan started` and `Job activeScan finished,
time taken: HH:MM:SS` records from the owned process log. It conservatively uses
the previous observation time for the Active deadline so polling latency cannot
extend the scan. Missing/duplicate boundaries, an excessive reported duration,
phase timeout, nonzero process exit, and missing reports all block PASS. The
native one-minute scan limit remains enabled. Timeout paths retain partial output
before mandatory teardown; no automatic retry is performed. These allocations
are finite diagnostic limits, not measured runtime feasibility or production
readiness evidence.
