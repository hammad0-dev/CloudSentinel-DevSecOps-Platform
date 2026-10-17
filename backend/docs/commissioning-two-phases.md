# Passive setup and separately authorized Active continuation

This supersedes the combined start/resume instructions in earlier commissioning
documents. No live operations or authorization records were created by this task.

## Gates and phases

`DAST_COMMISSIONING_SETUP_ENABLED=true` enables only the exact approved fixture
setup scope. It works with `DAST_ACTIVE_ENABLED=false`. The existing authenticated
`/start` route calls the existing Module 2 orchestrator, runs its static gates,
fixture staging and genuine passive-only baseline, then persists
`AWAITING_ACTIVE_AUTHORIZATION` and returns before Active DAST. There is no grant
issuance, waitForGrant, consumption, or Active job in that setup path.

Baseline runtime permission is a private server-issued WeakSet capability. A
copied object, ordinary grant, API phase parameter or enabled setup flag cannot
use it to execute an Active plan. Baseline plans are compared with the exact
passive-only generator. Namespace and tool commands continuously check permission.

Migration **014_active_dast_commissioning_phases.sql is required and unapplied**.
It records operator/project/execution, target, immutable fixture container,
baseline scan ID/hash, expiry and retained-runtime status. Composite foreign keys
preserve baseline/target execution ownership. Existing pipeline status remains
legitimately RUNNING during the bounded pause; the separate phase table records
the waiting state without inventing an unsupported pipeline status.

The fixture/gateway/networks remain lifecycle-owned during the short pause. Their
expiry aligns with the original staging authorization (at most five minutes).
The existing timer performs ownership-verified cleanup and invalidates the pause,
expires unused grants and ends the waiting execution. Explicit cleanup does the
same. Restarting the backend loses its private live registry: continuation then
fails closed. Unknown residual resources produce CLEANUP_FAILED, not an invented
successful cleanup or resumable state. Active cancellation is not implemented by
the paused-resource cleanup endpoint; it rejects that phase rather than claiming
to stop a running job.

## Real authentication and private approval

1. Use the application's normal login (`POST /api/auth/login` with the real user's
   email/password) or existing login flow. Do not mint a JWT using JWT_SECRET.
   Store the legitimate login response containing `token` locally in a regular,
   owner-only **0600** session file. Never paste credentials/tokens into logs/chat.
2. Use authenticated `GET /api/projects` to identify an actual owned disposable
   non-17 project. Do not guess user/project IDs or substitute Project 17.
3. After separate administrator approval, the supported server-side issuer is:

```bash
CS_COMMISSIONING_APPROVAL_ISSUANCE=authorized DAST_ACTIVE_ENABLED=false \
  node backend/scripts/commissioning-approval.js "$REAL_PROJECT_ID" "$PRIVATE_SESSION_FILE"
```

The CLI verifies the existing signed normal-user session and real database
ownership using SELECT only. It does not sign sessions, enable users, create
executions or grant privileges. It creates a random single-use approval token in
`approval.json` under a **0700** directory with **0600** file permissions. Output
contains only path, verified IDs and expiry. No token/secret is printed.

4. An administrator securely loads the returned scope and approval hash into the
   controlled backend process, before starting it under separate authorization:

```text
DAST_ACTIVE_ENABLED=false
DAST_ACTIVE_COMMISSIONING_ENABLED=true
DAST_COMMISSIONING_SETUP_ENABLED=true
DAST_ACTIVE_COMMISSIONING_ENROLLMENT_CONTEXT=<exact approval.json scope>
DAST_ACTIVE_OPERATOR_APPROVAL_SHA256=<exact approval.json sha256>
```

The token itself stays in the private file and goes only in the authenticated
enrollment request body. Do not hardcode it, log it, or modify shared `.env` as a
shortcut. Apply migration 014 only under separate migration approval first; the
operator/execution caller rejects a missing phase schema before database writes.

## Passive setup API sequence

All requests use the existing user's authenticated session. Secrets shown below
are placeholders, not credentials or ready-to-run authorization.

```http
POST /api/dast/active/<owned project>/commissioning/executions
{"approval":"<private server-issued token>"}

POST /api/dast/active/<project>/executions/<returned execution>/start
{}

GET /api/dast/active/<project>/executions/<execution>/phase
```

The returned execution ID comes from PostgreSQL. Setup must reach
AWAITING_ACTIVE_AUTHORIZATION with genuine baseline evidence. Phase status checks
fresh live resources before returning `resumable: true`; stored retention alone
is insufficient. No Active grant is issued or consumed automatically.

If separately approved and still eligible, the existing target and grant routes
can return the same fixture target and issue one UNUSED grant during the pause:

```http
POST /api/dast/active/<project>/executions/<execution>/targets
{"fixtureKind":"cloudsentinel-vulnerable-v1"}

POST /api/dast/active/<project>/executions/<execution>/grants
{"targetId":"<returned target UUID>"}
```

Issuance requires the waiting phase, real baseline and fresh retained runtime.
An unused grant cannot start a scan by itself. Cleanup/expiry makes it unusable.

## Active authorization without a backend restart

Normal production Active DAST stays disabled. A separately signed **scoped Active
enable flag** can authorize this one continuation without changing global flags
or restarting the backend and losing the paused runtime. Before setup, an
administrator configures `DAST_COMMISSIONING_CONTROL_FILE` to an unused absolute
file inside a private 0700 directory and configures a fresh private 64-hex
`DAST_COMMISSIONING_CONTROL_KEY` in the controlled server environment. These are
server-side configuration, never API inputs. The key is not a user JWT/token and
must not be printed or committed. An absent/invalid control file enables nothing.

Only after separate explicit Active approval, the administrator runs:

```bash
CS_COMMISSIONING_APPROVAL_ISSUANCE=active-continuation-authorized \
DAST_ACTIVE_ENABLED=false \
  node backend/scripts/commissioning-approval.js --continuation \
  "$REAL_PROJECT_ID" "$RETURNED_EXECUTION_ID" "$PRIVATE_SESSION_FILE"
```

The issuer must have the same configured private control key/path. It verifies
the genuine owner session and durable waiting execution, then writes (O_EXCL,
0600) an HMAC-authenticated permission containing exact user/project/execution,
`phase: ACTIVE_COMMISSIONING`, **activeEnabled: true**, and expiry bounded by the
paused lifetime and four minutes. This is a separate commissioning feature flag,
not a production readiness assertion. A request parameter alone cannot enable
it. Permissions, ownership, signature, scope and expiry are rechecked during
execution. No file means commissioning Active remains disabled.

Then the authenticated owner explicitly requests continuation:

```http
POST /api/dast/active/<project>/executions/<execution>/resume
{}
```

Resume verifies ownership, waiting state, expiry, genuine baseline, target and
fresh retained runtime plus one unused grant. A compare-and-set transitions the
phase once; replay cannot start another scan. The existing orchestrator's Active
continuation reuses its Module 2 service, atomic grant consumption, fresh scanner
containment, benign ZAP traffic verification and single SQLi/XSS job. Ordinary
production `assertReady()` remains unchanged. API callers cannot change server
flags or supply their own capability snapshots. There is no standalone scanner.

The environment-only commissioning Active flag/scope path remains available to a
controlled server already configured with `DAST_ACTIVE_ENABLED=true`; it also
requires the durable ACTIVE_COMMISSIONING transition. Global enablement alone
never resumes setup or consumes a grant.

## Stop and cleanup

```http
POST /api/dast/active/<project>/executions/<execution>/cleanup
{}
```

This invalidates the pause and unused grant and performs ownership-verified cleanup.
Do not claim future eligibility after cleanup. If the five-minute resource window
expires before separate approval, fresh setup needs a new execution/approval;
there is no automatic retry or reuse of a consumed grant.

Still missing in the live environment: migration 014 approval/application, a real
owner login/session, administrator-issued private approval and scoped server
configuration. Actual passive runtime and continuation behavior remain unverified.

Files changed: services/activeDastCommissioning.js, module2ActiveDast.js,
activeOperatorEnrollment.js, activeTargetEnrollment.js, activeScannerBinding.js,
activeZapRuntime.js, commissioningFixtureStage.js, activeRuntimeRegistry.js,
activeDastGrants.js, zapCommissioningTraffic.js, orchestrator.js,
commissioningPhases.js, commissioningControl.js; routes/dast.js;
migrations/014_active_dast_commissioning_phases.sql;
scripts/commissioning-approval.js; test/active-dast-commissioning.test.js,
zap-commissioning-traffic.test.js, commissioning-first-scan.test.js,
commissioning-orchestrator.test.js, commissioning-phases.test.js,
commissioning-approval.test.js; and this document.
