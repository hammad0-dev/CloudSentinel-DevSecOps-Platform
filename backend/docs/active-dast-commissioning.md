# First-run Active DAST commissioning

Commissioning is a separate authorization state, not production readiness.
Both Active DAST and commissioning default to disabled. This change executes
nothing during installation, import, tests, or readiness inspection.

Only a separately approved backend process may receive all of:

```text
DAST_ACTIVE_ENABLED=true
DAST_ACTIVE_COMMISSIONING_ENABLED=true
DAST_ACTIVE_COMMISSIONING_CONTEXT={"projectId":<real non-17 project>,"executionId":<real RUNNING execution>,"userId":<enabled owning operator>,"expiresAt":<UTC epoch milliseconds, at most 15 minutes away>}
```

These are preparation placeholders, not an executable authorization. Do not set
them in the shared `.env` or invent identities. The commissioning authorization
is server-selected, not accepted as a target/grant request-body flag. Targets and
grants additionally expire within five minutes. An expired commissioning scope
fails closed rather than falling back to ordinary production execution.

The existing authenticated target and grant routes remain the only callers:

```http
POST /api/dast/active/<project>/executions/<execution>/targets
{"fixtureKind":"cloudsentinel-vulnerable-v1"}

POST /api/dast/active/<project>/executions/<execution>/grants
{"targetId":"<returned target UUID>"}
```

An enabled database operator must own the RUNNING execution's project. A real
successful staging deployment and matching completed passive baseline are still
mandatory. No equivalence between a disposable fixture and a Minikube deployment
is asserted. Without that context commissioning remains BLOCKED. There is no
standalone scan endpoint or self-service operator elevation.

Enrollment binds the exact verified Python image, ZAP replacement image, pinned
Squid image, immutable gateway container, fixture container and scanner network.
The existing atomic grant UPDATE, expiry, ownership and target snapshot checks
remain in force. Audit reasons identify commissioning target enrollment, issuance
and consumption independently. Existing schema 013 permits these reason values;
no migration is added or applied.

The existing Module 2 stages lead to optional Active DAST. Commissioning alone
admits the six scan-dependent capabilities as unknown. Genuine recorded seven
rule/policy/add-on/report configuration is required, immutable images are freshly
inspected, and the actual ZAP namespace must pass the existing fresh containment
checks. Production `assertReady()` and its catalog remain unchanged and blocked.

Before Active jobs, a hashed read-only Python driver starts ZAP with loopback API,
private key, disabled update checks and the inspected Squid endpoint. Initialization
requires loaded add-ons/rules, valid policy XML, writable paths and safe socket
tables. Invalid/missing-key rejection requires valid-key health checks and matching
new daemon rejection logs. Target-specific rate 2/HOST and concurrency 1 settings
must be read back. Two bounded benign API `sendRequest` calls do not follow redirects.
Their echoed requests, exact synthetic response bodies and Squid Via headers must
match. Unique markers correlate exactly two Squid access records from the inspected
ZAP scanner IP. A helper cannot satisfy this application-traffic step. API response
shape or log-format uncertainty blocks execution instead of fabricating evidence.

The daemon must stop with observed process exit and listener removal before the
existing exact two SQLi/XSS plans run. Commissioning plans seed `id=1` and `q=hello`
and permit query variations only on the two exact paths. Detached autorun is polled
using fixed owned completion markers, bounded by grant expiry and cancellation.
Both SQLI/CWE-89 and XSS/CWE-79 findings are required for commissioning completion.
Existing normalization, Module 2 persistence/reporting and cleanup are reused.

Results include `authorizationState: COMMISSIONING`, `productionReady: false`,
and independent-review requirements. Observed benign spacing is not proof of
rate enforcement. Normal completion proves neither cancellation nor timeout.
No automatic production capability promotion occurs. Raw API keys/logs are not
returned in commissioning summaries; driver source is a private 0400 staged file
under the existing 0700 work directory and is cleaned with verified artifacts.

## Remaining runtime boundary

Offline mocks are not runtime proof. The new `sendRequest` response shape, Squid
log format, target-specific persisted rate settings across daemon/autorun restart,
and cancellation/timeout behavior require separately approved execution. The
replacement image must first be restored locally. No approval or live records
were created by this change. Next authorization must name real operator/project/
execution identities, allow the existing lifecycle's read-only staged mounts,
require fresh containment and authorize the exact bounded commissioning jobs.

Changed files for this task: services/activeDastCommissioning.js,
services/zapCommissioningTraffic.js, scripts/zap_commissioning_probe.py,
services/activeTargetEnrollment.js, services/activeRuntimeRegistry.js,
services/activeDastGrants.js, services/activeZapRuntime.js,
services/module2ActiveDast.js, services/dastActiveScanner.js, services/squidPolicy.js,
test/active-dast-commissioning.test.js, test/zap-commissioning-traffic.test.js,
test/zap_commissioning_probe_test.py, test/active-prerequisites.test.js,
and this document. Existing changes in those files are preserved.
