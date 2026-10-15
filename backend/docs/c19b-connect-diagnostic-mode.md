# CONNECT-only diagnostic mode

The persistent runner accepts `CS_ACCEPT_MODE=connect-diagnostic`. An absent mode
keeps full acceptance; explicit `full` is also accepted. Unknown modes fail
before provisioning. This mode is a diagnostic operation and cannot produce
full-containment READY/PASS or a runtime-ready attestation.

SecureGatewayLifecycle retains normal network allocation, fixture IP/mount
verification, pinned Squid policy staging, gateway attachment/ownership and
trusted client creation. RuntimeObservation retains normal independent Docker
identity/membership, native route/interface and active Squid policy checks.
Only then does it execute one existing trusted CONNECT probe. No positive HTTP,
other proxy, redirect or direct-TCP probes execute in this mode.

The native command output is associated privately with the actual probe object
through a WeakMap, never attached as raw output to its public result. A unique
`cloudsentinel-connect-diagnostic-<scanId>-*` directory is created locally with
mode 0700. `connect.json` is written exclusively with mode 0600 and explicitly
chmod'ed to 0600. It records the actual statuses, source/proxy identity and
observed evidence predicates. It retains bounded selected native curl connection
lines, CONNECT/Host request lines, status, Server/X-Squid-Error/Via/X-Cache
headers and header termination. Unknown connection formats are retained for
diagnosis without being accepted as proof. Unrelated verbose/environment lines
and other headers are omitted; credential-like values are redacted.

The file labels capture absence/truncation and MOCK_ONLY_NOT_VERIFIED versus
RUNTIME_OBSERVED provenance. No missing peer/header output is reconstructed.
Diagnostic results include curl-IP presence, actual socket observation/match and
ordering, independent gateway IDs, Squid/header/request predicates and statuses.
Public output contains the artifact path and bounded structured predicates, not
native verbose text.

The runner always executes ownership-verified lifecycle cleanup in finally,
including diagnostic, precondition and file-write failures. Partial diagnostic
files are removed on write/permission failure. A completed diagnostic file is
intentionally retained as evidence; it is not a staged container configuration.
Cleanup failures remain fatal. CLI exit 0 indicates a complete diagnostic DENY,
2 an incomplete or contradictory diagnostic, and 1 an operational/cleanup error.
None of those statuses establishes full containment.

Prepared command for a future separately approved attempt (not executed):

```bash
cd /home/hammad/CloudSentinel
DAST_ACTIVE_ENABLED=false \
CS_ACCEPT_MODE=connect-diagnostic \
CS_ACCEPT_PROJECT=c19b \
CS_ACCEPT_EXECUTION=cdiag1 \
CS_ACCEPT_SCAN=c19b-cdiag-7f39b6a1 \
CS_ACCEPT_HOST=c19b-fixture-7f39b6a1.test \
CS_ACCEPT_PORT=18080 \
node backend/scripts/dast-acceptance.js \
  > /tmp/c19b-cdiag-7f39b6a1.stdout.json \
  2> /tmp/c19b-cdiag-7f39b6a1.stderr.json
```

Fresh health, image, inventory, allocation and uniqueness checks are required
before the separately authorized runtime operation. All verification in this
implementation pass uses mocked Docker execution only.
