# C1.9B command compatibility and verdict repair

No containment lifecycle was executed for this repair. ZAP/Active scanning and
Module 2 were not invoked. All inspection processes used DAST_ACTIVE_ENABLED=false.

Pinned Nginx command checks genuinely executed in network-none, read-only,
cap-drop-ALL, no-new-privileges inspection containers with no host mounts or
published ports. The generated POSIX proxy wrapper and curl HTTP, redirect and
CONNECT option sets parsed with curl 8.12.1 (`--version`, no request). The nc
`-z -w 5` check printed supported usage with exit 1 because no destination was
provided; this is flag compatibility evidence, not a connectivity verdict.

`ip route list`, `ip -f inet6 route list`, and `ip address show` exited 0.
The real route lists were empty; the real interface output contained only lo,
127.0.0.1/8 and ::1/128. Production parsing accepted these observations without
inventing eth0 or treating network-none as scanner isolation. The captured output
is retained in test/fixtures/nginx-network-none.json. Eventual scanner isolation
still requires the independently inspected owned-network endpoint and rejects IPv6.

Both generated configurations passed parse-only checks from seekable files in
bounded tmpfs, running as the host artifact UID/GID, with read-only rootfs and no
network. Nginx `-t -c /dev/stdin` was not a reliable inspection method (non-seekable
input); the seekable-file check passed. Squid's default entrypoint was found to
prepend squid, start log helpers and initialize its default cache. Production now
uses /usr/sbin/squid directly so the configured foreground process is PID 1.
The fixture similarly uses /usr/sbin/nginx directly. All runs prohibit image pulls.

Verdicts:

- TCP exit 0 with empty zero-I/O output: ALLOW (direct connection established).
- TCP refusal, timeout, DNS/missing-tool/generic failures: INCONCLUSIVE.
- Invalid argument/option diagnostics: ERROR.
- Explicit ENETUNREACH: DENY for direct-network isolation only when corroborated
  by a fresh, immutable parser-issued proof for that client's network/IP/MAC,
  showing only the connected scanner route and a destination outside that subnet.
- Proxied DENY requires the inspected proxy peer, observed HTTP/CONNECT 403, an
  unambiguous Squid ERR_ACCESS_DENIED header and the appropriate command exit code.
  A TCP failure never proves a Squid policy denial.

Observation stops on the first inconclusive/error or contradictory result and
preserves partial probes in the thrown error. The runner reports sanitized probe
and cleanup diagnostics. Cleanup tracks partial resources, rechecks ownership,
retains residuals and does not repeat removal of successfully cleaned containers.

All temporary inspection containers were removed by exact ID after ownership
checks. Before/after container and network inventories matched. Complete runtime
HTTP/proxy/CONNECT/redirect/direct-TCP containment remains unverified until a
separately authorized disposable acceptance attempt.

## Verification results

- Focused adapter/network/fixture/gateway/client/observation/policy/runner/contract:
  104 passed.
- Complete backend: 208 passed. Frontend: 5 passed.
- Frontend production build passed (existing bundle-size warning).
- Changed JavaScript syntax, JSON parsing and tracked/untracked whitespace checks passed.
- Five network-disabled inspection containers were removed. The original nine
  containers and four networks remained unchanged.

Command evidence (exact argv, exit codes, sanitized stdout/stderr):

- `/tmp/cs-c19b-final-tools-68f7f50411.json`
- `/tmp/cs-c19b-config-tools-0fdac9a6db.json`
- `/tmp/cs-c19b-parse-bbaa91af67.json`

## Files changed in this repair

- `services/dastAcceptanceClient.js`
- `services/runtimeObservation.js`
- `services/runtimeNetworkText.js`
- `services/dastGateway.js`
- `services/dastFixture.js`
- `services/dockerAdapter.js`
- `services/ownedDockerNetworks.js`
- `scripts/dast-acceptance.js`
- `config/dast-gateway-contract-v1.json`
- `test/dast-acceptance-client.test.js`
- `test/runtime-network-text.test.js`
- `test/helpers/runtimeDocker.js`
- `test/gateway-integration.test.js`
- `test/dast-fixture.test.js`
- `test/docker-adapter.test.js`
- `test/owned-docker-networks.test.js`
- `test/dast-acceptance-runner.test.js`
- `test/dast-gateway-contract.test.js`
- `test/fixtures/nginx-network-none.json`
- `docs/c19b-final-readiness.md`
