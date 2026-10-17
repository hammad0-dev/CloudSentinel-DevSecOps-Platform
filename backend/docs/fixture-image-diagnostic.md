# Fixture image validation

The persistent diagnostic is `backend/scripts/fixture_runtime_validation.py`.
It requires separately approved execution, `--execute --evidence-dir <fresh-private-build-directory>`, and fresh preflight/build records. Importing its modules performs no Docker or network operations.

Image configuration comparison normalizes only absent `Cmd` to null on both sides. All other configuration fields, architecture, ownership/source labels and filesystem layer digests remain strict. The saved import fixture reproduces the historical failure; the original private report remains FAIL and is not rewritten.

The bounded native observer reports health, constant health under payloads, synthetic SQL injection, reflected XSS, scope rejection, per-request SQLite cleanup, UID/GID, source integrity, resources and network isolation independently. HTTP requests use only numeric loopback, disable environment proxies and have two-second deadlines. Container inspection requires network none, no published ports or host mounts, non-root execution, read-only rootfs and bounded owned tmpfs. All validation or cleanup failures exit nonzero. Incomplete checks cannot produce PASS.

Offline tests mock every subprocess in the persistent wrapper and all HTTP operations in observer tests. They are not real fixture runtime evidence. The genuine saved Docker response establishes only import compatibility. Future runtime validation requires fresh safety checks and separate authorization; no scan readiness is established by this diagnostic.
