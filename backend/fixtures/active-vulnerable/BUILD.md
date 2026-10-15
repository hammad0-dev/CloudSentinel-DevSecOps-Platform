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
