# C1.9B MALFORMED_ROUTES diagnosis

The single runtime attempt recorded only `MALFORMED_ROUTES`, empty diagnostics,
no probes and no explicit cleanup result in
`/tmp/c19b-runtime-26ce72f2.stderr.json`. Its stdout file is empty.
`/tmp/c19b-execution-after.json` records restored inventory and healthy workloads,
not the removed client's native route/interface output.

The runtime path is `RuntimeObservation.collect` -> trusted client `execute` ->
DockerAdapter `run` -> `verifyNetworkText`. The adapter returns stdout and stderr
separately. There is no evidence of swapped command streams. Parser failures
discarded their observation type and fixed validation message at the runner's
`failureReport` boundary. Successful command output was retained only in the
eventual successful evidence object, which was never returned.

`MALFORMED_ROUTES` can originate from IPv4/IPv6 route format, prefix or address
validation; interface header, address, link or completeness validation; or a
missing inspected endpoint identity. `routeCheck` also has an array check, but
the preceding parser constructs arrays. The saved report cannot distinguish
the remaining rules. Command failures normally have adapter-specific codes or
`INCOMPLETE_PROBES`. Exact original observation and rule remain unknown.

The previously captured genuine Nginx network-none fixture contains empty route
tables and loopback addresses. It parses successfully and correctly fails
scanner-isolation verification. It is not evidence of the failed attached
client's output. No failing real-output fixture has been invented.

Changes preserve existing accepted route/address formats and isolation checks.
Parser errors now identify observation and validation rule; runtime errors carry
the fixed command, actual exit status (null when unavailable), stdout/stderr
categories, byte/line counts and SHA-256 fingerprints. No native text, addresses,
environment values or credentials are added to diagnostic reports. Nonzero
status, missing command output or stderr warnings fail closed. The runner
serializes only bounded structured diagnostic fields.

Mocked regressions cover each observation type, missing interface output,
command failures, stream separation, ambiguous output, secret exclusion,
unverified evidence rejection and ownership-verified cleanup. Existing tests
retain default-route, IPv6, unknown-format and unexpected-interface rejection.

Status: PARTIAL. The confirmed diagnostic-loss defect is repaired. The original
route incompatibility or unsafe observation cannot be corrected without its
actual evidence. No live Docker operations or containment attempt were performed
in this diagnosis pass. A future explicitly authorized attempt could collect
the improved diagnostic, but successful acceptance is not established or
guaranteed ready by these source-only tests.
