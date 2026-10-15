# Active DAST implementation status — source only

## Discovered architecture

GitHub webhook routes call orchestrator.runPipeline. Its order is SAST (SonarQube),
Dependency (Trivy filesystem/SBOM), IaC, deployment (build/image Trivy gate and
Minikube rollout), passive DAST. Results use pipeline_executions, scan histories,
dast_scans/dast_findings, execution reports and CICDPipeline/DAST frontend pages.
SecureGatewayLifecycle owns two internal networks, a verified Nginx fixture,
Squid policy and the acceptance client. Its eleven-case acceptance genuinely
passed. That validates those resources, not an arbitrary ZAP container.

## Changes and reuse

The existing orchestrator now invokes module2ActiveDast after passive DAST only
when explicitly enabled. The stage never retries and failures stop completion.
Default behavior is unchanged. An optional Active DAST pipeline tile and an
owner-checked execution-report endpoint expose separate Active results; passive
DAST is not replaced. Migration 012 defines execution-bound Active records and
has NOT been applied. Active records include status, duration, findings and cleanup.

The existing SQLi/XSS Automation Framework plan is reused, including default-off
rules, bounded spidering, scan duration, one worker and delay. Its compatibility
with a future pinned image/add-on set is not claimed by offline string tests.
Normalization validates report scope, approved plugin IDs, classifications,
CWE/OWASP, confidence, sanitized evidence/remediation and duplicate fingerprints.
Empty completed reports differ from incomplete/error reports. Cancellation and
hard deadlines trigger cleanup through the runtime adapter interface.

## Disposable vulnerable fixture source

backend/fixtures/active-vulnerable/app.py is an unserved WSGI application using
only the Python standard library. /test/sqli?id=1 deliberately concatenates input
into an ephemeral in-memory SQLite query; id=1 OR 1=1 returns both synthetic rows.
/test/xss?q=hello deliberately reflects markup. Expected alerts include SQLi
40018 and reflected XSS 40012, CWE-89/CWE-79. These are expected future findings,
not evidence of an actual ZAP scan. No credentials, external integrations, disk
persistence, listener, image build or deployment is provided. Offline tests invoke
WSGI directly and open no sockets. Never serve this fixture outside isolation.

## Explicit remaining implementation blockers

This is PARTIAL, not runtime-ready. Real Active execution is blocked even with
DAST_ACTIVE_ENABLED=true. No mocked completion can enable production execution.
The runtime adapter currently exists only as an offline contract. Work remaining:

- Bind a provisioned vulnerable fixture to per-execution owner authorization.
  The internal issuer is not an owner-authenticated approval API; Module 2 has
  no grant provider and therefore blocks rather than inventing authorization.
- Generalize the proven lifecycle to the vulnerable fixture and ZAP container.
  The audited native binary and Squid must be independently verified against
  that actual scanner namespace; prior Nginx-client evidence is insufficient.
- Select an approved immutable local ZAP image and vulnerable runtime image,
  verify architecture/add-ons/commands without pulling or assuming digests.
- Implement proxy wiring, exact route scope, redirect/DNS pinning, bounded
  scanner process output, rate limits and cancellation/cleanup in that adapter.
  The existing Squid policy permits any path on the fixture origin, so it must
  gain route-level enforcement before active scanning.
- Verify all requested jobs/rules/rate semantics against the pinned ZAP runtime.
- Apply migration 012 only under separate database authorization, wire approval
  and successful Active findings into unified aggregation and frontend details.
  Unified reports now expose Active records/findings separately and mark unavailable schema; owner-approval and full frontend details still need completion.
- Independently validate containment and SQLi/XSS findings in an approved run.

No service environment was enabled and no Docker, Kubernetes, database, Module 2
or Active scan was executed. IPv6 acceptance remains structural, not packet-level.
