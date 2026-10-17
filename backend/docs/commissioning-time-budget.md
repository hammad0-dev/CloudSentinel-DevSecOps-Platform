# Commissioning deadline budget

Update: the retained-scanner path now has a separately enforced 165-second
budget. See [commissioning-warm-path.md](commissioning-warm-path.md). The cold-path
analysis below remains historical evidence; warm-path timing is not yet measured.

Production Active DAST remains disabled. This source change neither issues an
approval nor establishes successful Active execution.

## Retained real timing evidence

Execution 27 / baseline 16, retained in
`/tmp/cs-p11-passive-final-e1/database-result.json`:

| Observation | UTC |
| --- | --- |
| Pipeline started | 2026-10-16 16:16:31.941 |
| Fixture authorization window began | 2026-10-16 16:16:54.637 |
| Baseline findings persisted | 2026-10-16 16:19:01.142 |
| Retained authorization expired | 2026-10-16 16:21:54.637 |

The window start is derived from the unchanged 300-second authorization cap
and its recorded expiry, with the enclosing operator approval later than that
expiry. Fixture preparation, baseline execution and persistence used 126.505
seconds of that window; only 173.495 seconds remained. The baseline scan row's
started/completed timestamps measure persistence, not Java startup or scanning.
There is no retained breakdown demonstrating an upper bound for each Active
startup, namespace verification, report or cleanup step. Expiry invalidation was
recorded at 16:22:15.745, 21.108 seconds after expiry; this is not proof that
cleanup can always finish in that time.

## Enforced candidate budget

`commissioningBudget.js` reserves 120 seconds for fresh startup/containment and
benign correlated traffic, 60 seconds for the Active job, 15 seconds for report
processing, and 30 seconds for cleanup: **225 seconds total**. These are scheduling
reserves, not measured runtime guarantees. Cleanup failure or overrun remains a
failure. No authorization expiry is increased.

The locally extracted Automation Framework schema in
`backend/config/zap-diagnostic-contracts.json` declares integer minute limits.
Commissioning now selects `maxScanDurationInMins: 1`, retaining all seven rules,
LOW strength/threshold, rate 2/sec, concurrency 1 and both existing endpoint seeds.
90 seconds is not encoded as a fractional unsupported minute setting. Ordinary
production plans and passive-only plans are unchanged. A time-limited job is not
proof that every rule finished; valid native completion/report evidence and both
SQLi/XSS findings are still mandatory.

The earliest durable execution expiry, retained authorization expiry, consumed
grant expiry, operator execution scope and authenticated signed continuation
expiry governs Active work. Issuance and resume reject insufficient time before
grant insertion / phase transition. The official continuation issuer also rejects
insufficient time before writing its private signed file. It still requires a
genuine `AWAITING_ACTIVE_AUTHORIZATION` row, RUNNING execution, owning user and
retained runtime; it cannot sign for a future execution before passive setup.

A cancellation signal covers provisioning, namespace/startup verification,
traffic and autorun rather than starting only after provision. Work is aborted
30 seconds before the earliest deadline; bounded in-flight operations settle
before cleanup so late provisioning cannot race resource removal. Immediately
before autorun at least 105 seconds must remain (scan/report/cleanup). Native
completion and report validation remain required. Late results cannot be recorded
as successful findings; Module 2 also fences a result around database persistence.
Cleanup remains ownership verified and is attempted even after an overrun.

## Readiness and shortest legitimate sequence

**Cold path BLOCKED on demonstrated timing.** Execution 27's remaining 173.495 seconds does
not meet the 225-second reserve. Even instant human approval would not fix this.
To fit without extending TTL, pre-pause overhead must be at most 75 seconds,
at least 51.505 seconds below the observed 126.505 seconds, or finer genuine timing
evidence must justify smaller reserves while preserving all checks. A candidate
design change is retaining/reusing the already verified baseline scanner instead
of destroying it and starting two fresh Java runtimes on continuation; that design
is now source-integrated with fresh verification as documented in the warm-path
addendum; its runtime savings remain unverified. Namespace, identity, policy,
authorization and fresh containment verification must remain intact.

Once that timing prerequisite is established:

1. Verify real owner login; issue fresh setup approval using the official CLI.
   Prepare the private environment, an unused control-file path and its private
   key before one authorized backend restart. Preserve global Active disabled,
   orphan cleanup disabled and the existing offline Trivy settings.
2. Create one execution using authenticated commissioning APIs. Run its mandatory
   static gates, fixture staging and genuine passive baseline. No retries.
3. Immediately GET its phase; require genuine baseline, fresh retained runtime,
   resumable status and sufficient remaining time. Only then invoke:

   ```bash
   CS_COMMISSIONING_APPROVAL_ISSUANCE=active-continuation-authorized \
   DAST_ACTIVE_ENABLED=false node backend/scripts/commissioning-approval.js \
     --continuation 11 "$RETURNED_EXECUTION_ID" "$PRIVATE_OWNER_SESSION"
   ```

   The issuer needs the same private control key/path loaded by the backend.
4. Authenticate to enroll the exact retained fixture, issue one grant and POST
   resume immediately. Each time gate is checked again; no blind automatic retry.
   If issuance is blocked, call the authenticated execution cleanup endpoint and
   independently verify removal; do not leave a known ineligible pause waiting
   for its expiry timer.
5. Require actual completion, scoped findings, report/database evidence, observed
   rate evidence and ownership-safe cleanup. Never promote production readiness
   based on this commissioning attempt.

Do not run another passive pipeline merely to hit the known insufficient-time
gate. No runtime, restart, grant, migration or database mutation is authorized by
this document.

## Files changed by this correction

- Services: `commissioningBudget.js`, `module2ActiveDast.js`,
  `activeZapRuntime.js`, `activeDastGrants.js`, `commissioningPhases.js`,
  `orchestrator.js`, `dastActiveScanner.js`.
- CLI: `backend/scripts/commissioning-approval.js`.
- Tests: `commissioning-budget.test.js`,
  `commissioning-budget-persistence.test.js`, `commissioning-phases.test.js`,
  `commissioning-approval.test.js`, `commissioning-first-scan.test.js`,
  `active-dast-grants.test.js`, `active-dast-commissioning.test.js`.
- This timing and execution procedure document and `commissioning-first-scan.md`.
