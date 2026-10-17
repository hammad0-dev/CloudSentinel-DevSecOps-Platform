# Passive Automation Framework output investigation

Execution 26 remains FAILED. Its retained database result identifies
`ZAP_STARTUP_LOG_UNVERIFIED`, but neither the Automation command log nor its
unrecognized line survived cleanup. The empty late capture is not command
evidence. No historical result has been changed.

The confirmed parser compatibility gap is independently established by the
[Automation 0.60.0 message definitions](https://github.com/zaproxy/zap-extensions/blob/automation-v0.60.0/addOns/automation/src/main/resources/org/zaproxy/addon/automation/resources/Messages.properties):
`automation.info.jobstart`, `automation.info.jobend`, and
`automation.out.title.good` emit console progress/completion rather than elapsed
Log4j records. Only those narrow formats are newly recognized. All other unknown
records, malformed control characters, ERROR/FATAL records and concrete startup
failures still block. These examples are source-derived formats, not execution
26 output. Recognition never replaces command exit, report parsing, or containment.

On a failed Automation command, `ActiveZapRuntime.scan()` now awaits private
evidence persistence before the baseline error path tears down the container.
`zapCommissioningTraffic.executePlan()` also attempts capture of partial logs on
command/poll failures, only after fresh ownership verification. A persistence
failure is attached separately and cannot replace the original failure or stop
cleanup.

Evidence is written to a unique `cs-zap-automation-p<project>-e<execution>-*`
directory (0700), with `output.json` (0600, exclusive/no-follow creation). It
records native byte counts/hashes, bounded redacted streams, named classification,
unrecognized line numbers/hashes/excerpts, truncation/missing-output flags and the
actual exit status where observed. The detached command merges stdout/stderr;
that layout is recorded rather than reconstructing separate streams. A failed
log-read command's status/stderr is distinguished from the Automation process.
Evidence is outside lifecycle staging and survives resource cleanup. API keys,
credentials, sensitive headers and local filesystem paths are redacted before
truncation. Evidence files are not public API response bodies or general logs.

## One future targeted validation

No runtime command is authorized or executed by this source change. Do not rerun
Module 2 or its static stages merely to inspect console formatting.

The targeted procedure is one passive-only Automation command in the existing
lifecycle-owned ZAP/gateway/disposable Python environment:

1. Use the same immutable images and hardening/ownership contracts. Obtain a
   genuine diagnostic-only capability; never construct a production baseline
   authorization or reuse execution 26's failed authorization.
2. Keep production Active DAST disabled. Generate the fixed passive plan using
   `commissioningPlan(verifiedOrigin, {baseline: true})`. Verify the plan contains
   only the two fixed benign requestor entries, passiveScan-wait and traditional
   JSON report. No spider/activeScan job, arbitrary origin or attack data.
3. Retain required fresh identity/namespace/route/policy preconditions. Do not
   repeat the unrelated SAST/Dependency/IaC stages or substitute a broad full
   acceptance run for this targeted operation.
4. Run the existing `executePlan()` path once with the existing proxy, loopback
   binding, authenticated API and fixed `/zap/wrk/plan-0.yaml` input. Capture its
   complete bounded output before classification and ownership-safe teardown.
5. Feed the captured output through the production classifier, verify process
   exit and parse the genuine report independently. Unknown output stops the
   procedure; do not retry or claim a completed production baseline.
6. Verify zero owned residuals and unchanged original resources/Project 17.

## Disabled-by-default passive autorun entry point

`--passive-autorun` now performs the fixed two-request correlation and then exactly
one passive plan. A private one-use permit binds the immutable scanner/gateway,
exact command hash, scope and expiry. It cannot supply a production authorization
or grant, arbitrary plan, URL or job. The production `executePlan()` path checks
this separate permit; its ordinary production authorization checks are unchanged.
The plan must equal the production passive generator and contain only requestor,
passiveScan-wait and report jobs. Loaded pscan 0.6.0 is required. The daemon is
shut down with authenticated API access and its actual zero exit marker observed
before autorun reuses the home directory and loopback port.

After offline tests and fresh safety preflight, one separately approved attempt:

```bash
DAST_ACTIVE_ENABLED=false node backend/scripts/zap-containment-diagnostic.js \
  --execute --scope zap-python-containment --scan pa-p11-1016-a3 \
  --project 11 --execution 26 --ttl 600 --passive-autorun
```

Project/execution numbers are diagnostic labels only; execution 26 is not resumed
or mutated. The existing lifecycle's namespace/route/policy preconditions and
containment checks remain mandatory. No Module 2 or static stages run. Native
Automation output is retained privately on both success and failure before
classification; failure/persistence errors prevent PASS. A zero process exit and
an in-scope parsed nonempty-site traditional JSON report are independently
required. Reports are not persisted to PostgreSQL. Successful output is explicitly
diagnostic-only, with full containment/readiness promotion false. Rate enforcement,
Active findings, completion/cancellation/timeout and actual redirect behavior are
not inferred. Ownership-safe cleanup always runs. Never retry a failed attempt
automatically or use the existing response-only option as an autorun substitute.

## Retained first diagnostic attempt

The single `pa-p11-1016-a1` runtime attempt reached passive autorun after genuine
initialization, containment and two-request correlation. It exited 1 with
`ZAP_STARTUP_LOG_UNVERIFIED`; native ZAP also exited 1 and printed an unsupported
file-type rejection for `zap.sh`, followed by usage help. The exact output was
preserved privately before cleanup at
`/tmp/cs-zap-automation-p11-e26-Fuu9a3/output.json`. Cleanup and independent
inventory/Project 17 checks passed. No retry occurred and no passive report or
successful passive completion was established.

The new diagnostic had supplied the executable in the options array, while
`executePlan()` already invokes it in its shell wrapper. This was corrected
offline to pass options only, matching the existing production
`ActiveZapRuntime` call contract. A regression rejects duplicate executable
arguments before any command. Usage output is not allowlisted as benign: the
unsupported-file message is classified as failure. This diagnostic defect does
not establish execution 26's lost historical output or imply that its original
production call duplicated the executable. The corrected diagnostic still needs
one new explicitly approved runtime attempt; a1's historical result stays BLOCKED.

## Second attempt: real passive execution and report observed

`pa-p11-1016-a2` executed exactly once with the corrected argument contract. The
native Automation process exited **0**. An independent, ownership-verified fixed
report read before teardown parsed one exact fixture site and six passive
findings using the production extractor. Its report SHA-256 and scope checks are
retained in `/tmp/cs-passive-autorun-1016-a2/independent-report.json`.

The diagnostic runner nevertheless exited 1/BLOCKED on 13 unrecognized progress
records. These were parameter progress, benign URL requests and report generation,
not startup errors. All thirteen original record SHA-256 values and byte lengths
were matched exactly to the fixed plan's known, non-secret message values offline;
this identified the redacted records without substituting guessed observations.
The regression fixture records these genuine fingerprints. The parser now accepts
only the fixed passive values/formats; unsupported values, paths, jobs and genuine
errors remain blocking. Sources include Automation 0.60.0's `automation.info.setparam`
and `automation.info.requrl`, plus Reports 0.46.0's
[`reports.automation.info.reportgen`](https://github.com/zaproxy/zap-extensions/blob/reports-v0.46.0/addOns/reports/src/main/resources/org/zaproxy/addon/reports/resources/Messages.properties).

`/tmp/cs-passive-autorun-1016-a2/offline-verification.json` distinguishes native
process/report PASS from the historical runner BLOCKED and the corrected-record
replay PASS. The full raw stdout was not replayed; the complete original unknown
record set was byte-verified and replayed. No runtime retry occurred. Native
evidence remains `/tmp/cs-zap-automation-p11-e26-HIES4e/output.json`. Cleanup,
original nine/four IDs, images, backend and Project 17 were independently verified.
No baseline or production readiness was persisted. Execution 26 remains FAILED.

Read-only continuation checks found a valid owning-user session, secure private
configuration, no running jobs and an expired commissioning approval. Before a
new Module 2 PASSIVE_SETUP, obtain a legitimate fresh approval, authorize/reload the
backend with current source and private configuration, and create one new execution.
Do not reuse execution 26, claim a persisted baseline from this diagnostic, or start
Active DAST without its genuine waiting phase, enrollment and single-use grant.
