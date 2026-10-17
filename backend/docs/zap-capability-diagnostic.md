# Non-scanning ZAP diagnostic contract

The persistent runner is `backend/scripts/zap_runtime_diagnostic.py`. Historical
scripts and result files under `/tmp/cs-zap-complete-eumqv32d` are retained as
evidence, not executable preparation for another attempt. This correction does
not authorize another execution.

The runtime entry point requires `--execute --evidence-dir <fresh-private-dir>`.
That directory must be owned by the operator, mode 0700, and contain a fresh
`preflight.json` and `before.json` using the established inventory/health evidence
format. Existing result/import evidence prevents reuse. A future separately
approved run must reconfirm the nine-container/four-network baseline, workload
health, unused image tag/name, local archive and ownership-safe cleanup. No
preflight or Docker operation was performed while implementing these corrections.

The runner imports only the previously verified local archive, at most once,
and creates at most one network-disabled hardened container. No BuildKit,
downloads, fixture, target traffic or scan job is part of this diagnostic.
Every subprocess has a deadline; execution has a 900-second budget with cleanup
still permitted afterwards. Evidence remains in the private directory with
0600 files. The decision module never starts a subprocess or changes a catalog.

## Authentication

A valid-key protected operation must return HTTP 200 and `Result: OK` before and
after the rejection tests. Immutable daemon identity, running state, version and
both native TCP listener tables are checked around the tests.

Missing and wrong keys may return an explicit `bad_api_key` response. The genuine
2.17.0 runtime instead closes the connection. That outcome is accepted only for
`RemoteDisconnected` with complete bounded observations and exactly matching
fresh daemon rejection lines for each request. Logs are compared separately by
stdout/stderr append-only deltas; historical warnings cannot establish success.
Timeouts, generic HTTP 403, crashes, wrong identities, unrelated connection
errors, contradictory success data and missing/truncated logs fail closed.

## Confirmed API and YAML corrections

Local inspection of the exact archived core/add-on classes and templates found:

* Per-rule threshold/strength setters require singular `id`; call them once for
  each of the seven approved IDs. `enableScanners` uses comma-separated `ids`.
  All other scanners are disabled first. Readback must show exactly seven
  enabled rules at LOW threshold/strength, without ambiguous or duplicate IDs.
* Genuine option views return keys `ThreadPerHost` and `HostPerScan`, without
  the endpoint's `option` prefix. Set/read both to one. Earlier offline
  interpretation of the class output was wrong; the saved runtime response is
  authoritative and now has a direct regression.
* Network 0.29.0 supports `addRateLimitRule` and `getRateLimitRules`, with
  description, enabled, matchRegex, matchString, requestsPerSecond and groupBy.
  Compare every field in the readback; configuration is not traffic enforcement.
* Reports 0.46.0 returns `{generate: <actual path>}`, not `Result: OK`. Require the
  exact traditional-json template, expected private output path and actual JSON
  accepted by the existing report shape (`site: []` for empty data).
* Automation 0.60.0 has runPlan, stopPlan, endDelayJob and planProgress, but no
  `plans` view or non-running load/validate-plan action. None of its actions is
  invoked. Structural compatibility is checked offline against authentic
  bundled templates; job behavior remains unverified.
* Spider 0.20.0 uses `maxDuration`, not `maxDurationInMins`. The real generator
  now emits the supported two-minute bound and `threadCount: 1`. The policy
  threshold `"Off"` is quoted to remove YAML scalar ambiguity.

`backend/config/zap-diagnostic-contracts.json` records authentic template bytes,
archive/class/template SHA-256 values, and previously observed image identities.
The offline YAML comparison uses already-installed PyYAML, rejects duplicate
keys and unsupported parameters, and never starts ZAP. Missing parser/evidence
is UNVERIFIED. This does not establish successful execution of an AF job.

## Results and exit codes

| Final status | Exit | Meaning |
|---|---:|---|
| PASS | 0 | Every mandatory non-scanning diagnostic check and cleanup passed |
| PARTIAL | 2 | Prerequisites passed, but a mandatory capability remains UNVERIFIED |
| BLOCKED | 3 | A security prerequisite failed, or mandatory checks are NOT_RUN |
| FAIL | 1 | A reachable capability, cleanup or independent postflight failed |

Independent results are retained for initialization, authentication, policy,
rate configuration, concurrency, status listing, cancellation contract, JSON
report export and AF schema compatibility. A local policy/rate/report failure
does not skip unrelated later checks. Security prerequisites still block unsafe
operations. Cleanup cannot turn a failed diagnostic into PASS.

Status listing requires a real empty scan list. Cancellation/status UI discovery
requires one `zapform` with `action="override"`, an enabled empty `scanId` input,
and the exact `zap-component`, `zap-type`, `zap-name` submit attributes. Missing,
duplicate, external-action and contradictory fields fail. Discovery is not
proof of a successful production cancellation/status operation. These descriptions
are inspected without calling stop, inventing scan IDs or starting a job. Actual
completion, cancellation and rate enforcement are always separately UNVERIFIED
in this non-scanning diagnostic and are not mandatory diagnostic checks.

All successful reports contain `diagnosticOnly: true`, `activeExecutionReady:
false`, and retain production readiness BLOCKED. The production capability gate,
disabled default, fixture and database prerequisites are unchanged.

## Offline replay

`backend/test/zap_capability_diagnostic_test.py` preserves identifiable genuine
authentication and initialization fixtures. Unexecuted API success responses
and process outcomes are explicitly mocked. The complete wrapper replay mocks
every subprocess, archive import and cleanup; it is not image or runtime proof.
Separate tests compare the genuine plan generator with authentic schema bytes,
compile every embedded native Python payload and exercise native HTTP transport
using mocked urllib (no sockets). Backend tests invoke this suite automatically.

`zap-capabilities-2aspu6vu.json` preserves the complete sanitized genuine API
responses, including both actual option keys and actual UI forms. Its saved
historical runner status remains FAIL/1. Corrected offline replay is a separate
test result and never rewrites the original private runtime artifacts. Log timing
in that replay uses chronological prefixes of retained genuine lines; it is not
a new runtime observation.
