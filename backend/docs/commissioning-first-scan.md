# One-job fixture commissioning

This is source-tested preparation, not runtime evidence or authorization. No
operator, execution, deployment, baseline, target, grant or scan was created by
the implementation task. Both flags remain disabled in the shared environment.

Previously `module2ActiveDast.plans()` mapped each of the two endpoint paths to
an independent plan, each containing an Active Scan job. Commissioning now emits
one plan with two requestor seeds, an exact two-path context, one dedicated
seven-rule policy and exactly one Active Scan job. Ordinary production plans
retain their prior behavior. Commissioning has no spider job. All other rules
are OFF; enabled rules use LOW/LOW, threadPerHost 1 and 500 ms configured delay.
The Active job limit is one minute, with one minute per rule and ten alerts per rule.
The deadline budget also reserves startup, reporting and cleanup time; see
[commissioning-time-budget.md](commissioning-time-budget.md). A bounded job is
not proof that every rule completed or that the end-to-end budget fits.
The runtime polls owned Squid records and aborts above a 600-record execution
budget; this is an observed cutoff, not a packet-perfect request counter.

Authentic requestor and passiveScan-wait schemas were extracted locally from the
verified image archive and saved with SHA-256 values in
`test/fixtures/zap-commissioning-job-schemas.json`. The passive job belongs to
pscan 0.6.0, not the Automation archive. Before baseline execution the runtime
requires exactly that loaded pscan version; archive presence is not loading proof.

## Private operator and execution preparation

A legitimate existing user must own an existing non-17 project. No JWT role
claim can enable an operator. An administrator must separately authorize that
user/project in the bounded backend process, using:

```text
DAST_ACTIVE_ENABLED=true
DAST_ACTIVE_COMMISSIONING_ENABLED=true
DAST_ACTIVE_COMMISSIONING_ENROLLMENT_CONTEXT={"projectId":<real owned project>,"userId":<real authenticated user>,"expiresAt":<epoch milliseconds, at most 15 minutes away>}
DAST_ACTIVE_OPERATOR_APPROVAL_SHA256=<SHA-256 of a private random 64-hex-character approval token>
```

Do not put the token in logs, shared `.env`, command-line arguments or reports.
Using the real user's existing authenticated session, the supported request is:

```http
POST /api/dast/active/<projectId>/commissioning/executions
Authorization: Bearer <existing user session>
Content-Type: application/json

{"approval":"<private approved token>"}
```

One transaction locks the project/approval, verifies the actual user and owner,
rejects an existing active execution and reused approval, creates a TRIGGERED
execution with `INSERT ... RETURNING`, enables the scoped operator and audits the
approval. Only the returned database ID is bound into the backend's private scope.
There is no predicted execution ID or synthetic identity. Schema 013's global
operator role is restricted by commissioning approval audit records and the
private scope at authorization gates, so this enrollment cannot confer authority
over other owned projects/executions. Approval replay is rejected under a
transaction advisory lock. Existing-execution operator enrollment is also supported
at `/active/<project>/executions/<execution>/operator` with the exact execution
authorization configured through `DAST_ACTIVE_COMMISSIONING_CONTEXT`.

## Existing Module 2 execution

```http
POST /api/dast/active/<project>/executions/<returned execution>/start
Authorization: Bearer <same existing user session>
Content-Type: application/json

{}
```

The route atomically admits only the owning enabled operator's TRIGGERED execution
and invokes the existing `orchestrator.runPipeline`; repeated start is rejected.
The existing SAST/dependency/IaC stages and critical gates remain in order. For
this exact commissioning scope only, the deployment stage uses the verified Python
fixture instead of deploying a repository to Minikube. No arbitrary repository,
URL or image is accepted by the adapter; the project record is not rewritten.

The adapter provisions the actual lifecycle-owned fixture/gateway, verifies their
identities and containment, starts the verified ZAP runtime and runs a passive-only
plan: two benign requestor seeds, passiveScan-wait and traditional JSON report.
No Active Scan exists in that phase. Successful real output and report parsing
are required before deployment/baseline records are written. Passive findings are
persisted with the existing `persistCompletedScan` transaction. Failure is recorded
accurately; no zero-findings result is invented. Baseline and staging records are
explicitly labelled fixture commissioning and bound to the actual fixture ID and
report SHA-256. A private live registry plus independent database relationships
must match; copying database rows cannot manufacture that process-local proof.

Target enrollment reuses this same live fixture. Existing authenticated target
selection returns its bound UUID; it cannot provision a replacement fixture.

```http
POST /api/dast/active/<project>/executions/<execution>/targets
{"fixtureKind":"cloudsentinel-vulnerable-v1"}

POST /api/dast/active/<project>/executions/<execution>/grants
{"targetId":"<returned target UUID>"}
```

One target and one grant per execution are still enforced by schema 013. Fresh
staging/baseline, ownership, expiry and immutable target checks precede atomic
consumption. Baseline scan ID and report hash join the grant's independently
compared target snapshot. Pending enrollment expires and cleans up. The baseline
scanner/helper are removed while the owned fixture/gateway remain for the Active
phase. Fresh Active scanner namespace checks and ZAP-originated benign/Squid
correlation are repeated before the single Active job. Existing normalization,
Module 2 result persistence and execution report/dashboard paths are reused.

All failure paths attempt ownership-verified cleanup. Orchestrator failures before
Active DAST also clean pending targets. Cleanup failure remains distinct from probe
or scan success. Commissioning never promotes normal production capability flags.

## Next authorization and remaining runtime evidence

The smallest next operation is one bounded commissioning execution with the exact
real owner/project, local verified ZAP import and these private API calls. No such
operation was performed here. It requires a controlled backend process running
this source, the immutable local images, private approval material, fresh health/
containment checks and explicit runtime approval. The live server was not restarted.

Still unverified: actual loaded pscan 0.6.0/job behavior in this path; requestor
seeding across ZAP restarts; baseline completion/export; target-specific rate
configuration persistence; actual rate/concurrency enforcement; Active completion,
findings and cancellation/timeout behavior. Unsupported or missing observations
block execution. Normal completion is not cancellation/timeout evidence.

Files changed in this task: `services/dastActiveScanner.js`,
`services/module2ActiveDast.js`, `services/activeZapRuntime.js`,
`services/zapCommissioningTraffic.js`, `services/activeOperatorEnrollment.js`,
`services/activeDastCommissioning.js`, `services/activeDastPrerequisites.js`,
`services/activeTargetEnrollment.js`, `services/commissioningFixtureStage.js`,
`services/activeRuntimeRegistry.js`, `services/activeDastGrants.js`,
`services/orchestrator.js`, `routes/dast.js`,
`test/active-dast-commissioning.test.js`, `test/commissioning-first-scan.test.js`,
`test/commissioning-orchestrator.test.js`,
`test/fixtures/zap-commissioning-job-schemas.json`, and this document.

This document supersedes the two-plan and no-fixture-equivalence descriptions
in the earlier commissioning preparation document.
