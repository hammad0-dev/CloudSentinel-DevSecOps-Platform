# Future reproducible fixture build

No image was built. No base/final digest is supplied because no compatible Python
image has been verified. The build has no downloads, package installation or
external dependencies: Python, SQLite, WSGI, tempfile and health checking are
standard-library capabilities that the approved base must demonstrate.

Before a separately authorized build, record the immutable Python base reference,
Linux/amd64 metadata, Python/SQLite versions, standard-library capabilities and
source SHA-256. Pass only that digest reference as PYTHON_BASE (no default/tag
fallback). Use the exact Dockerfile/app.py build context, fixed builder/version,
SOURCE_DATE_EPOCH and platform, no network, and no pulling. Verify reproducibility
with two independent builds; do not claim reproducibility from this definition
alone. Record the resulting immutable image ID/RepoDigest and source provenance;
register it only after independent image/capability checks.

Runtime requires read-only rootfs, /tmp as a bounded writable tmpfs, UID/GID
10001:10001, dropped capabilities, no-new-privileges, internal IPv4-only fixture
network, no published ports and lifecycle ownership labels. SQLite uses per-request
synthetic files under /tmp, deletes them on exit, and has no host persistence.
/health returns fixture-ready; /test/sqli?id=1 and /test/xss?q=hello are deterministic
deliberately vulnerable endpoints. Health is local-only; Active proxy scope permits
only the two test paths. The default WSGI server has one request worker.

## Current base-image prerequisite

Read-only local Docker inventory during the diagnostic-closure task contained no
approved standalone Python base image. No immutable Python base reference,
Python/SQLite version or fixture-image digest is established. Existing ZAP,
Minikube and application images are not approved substitutes.

The smallest next artifact step requires separate approval: supply/import a
digest-verified official Python Linux/amd64 image archive, or authorize obtaining
an explicitly selected official Python image and recording its immutable digest.
No candidate tag is an approved immutable identity. Then use one network-disabled
capability inspection to establish `python3`, `sqlite3`, `wsgiref.simple_server`,
`tempfile`, `json`, `urllib.request`, the Python/SQLite versions, numeric-user
10001:10001 execution and required writable `/tmp` behavior. Do not install
packages. A fixture build and its health/endpoint validation need separate scope.

Construction must not assume `--pull=false --network=none` prevents BuildKit
registry/frontend resolution. Verify the chosen builder is fully offline first,
or prepare a validated local-archive assembler for the approved Python base.
The verified ZAP-specific assembler is not automatically a fixture assembler.
This definition alone proves neither a final image identity nor reproducibility.

## Future containment delivery

Reuse `SecureGatewayLifecycle` and its existing injectable fixture-service
interface, not another pipeline or fixture application. Its default
`dastFixture.js` still creates pinned Nginx and cannot serve this Python app.
Before scanning, a fixture implementation must bind the verified Python image,
return independently inspected immutable ID/network/IP evidence, support partial
provisioning callbacks and use the same ownership-verified cleanup interface.

Use only the owned internal IPv4 fixture network, unique scan/role labels,
UID/GID 10001:10001, read-only rootfs, dropped capabilities, no-new-privileges,
bounded CPU/memory/PID/time limits and a single `/tmp` tmpfs (initially 16 MiB,
rw/noexec/nosuid/nodev, uid/gid 10001, mode 0700). Verify effective tmpfs settings
and available capacity; 16 MiB is a proposed bound, not a measured runtime result.
No host port, host/database mounts, Docker socket or external network is permitted.
Verify image provenance, hostname/origin, Docker-assigned IP and network membership
before generating the exact SQLi/XSS path policy. `/health` is available only for
local health checks and is not added to the scanner path allowlist.

Future health/endpoint validation must establish constant `/health`, single-row
`id=1` versus two-row `id=1 OR 1=1`, literal reflected script input, 404 outside
scope, cleanup of per-request SQLite files, read-only-rootfs compatibility and
zero owned residual resources. Offline unit tests exercise these handlers directly
without opening a server or sending requests.
