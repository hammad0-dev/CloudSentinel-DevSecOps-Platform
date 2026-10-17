# Isolated ZAP diagnostic inspection regression

The previous diagnostic was `/tmp/cs-zap-init-712c7658-wtf4wb6r/execute.py`.
It incorrectly required `len(inspect['Mounts']) == 3`. The retained genuine
inspection has `Mounts: []` and all three configured mounts in `HostConfig.Tmpfs`.
Its Docker health status was still `starting`, as expected before ZAP readiness.

That script now calls the repository's pure
`backend/scripts/zap_diagnostic_inspection.py::validate_inspection` instead of
the inline assertion block. Future prepared diagnostics must reuse this checked
validator. The validator performs no subprocess or network operations.

It now requires these `HostConfig.Tmpfs` paths, including the narrowly scoped
profile correction described in `zap-writable-paths.md`:

| Path | Capacity | UID:GID | Mode |
| --- | --- | --- | --- |
| `/home/zap/.ZAP` | 256 MiB | 1000:1000 | 0700 |
| `/tmp` | 64 MiB | 1000:1000 | 1777 |
| `/zap/wrk` | 64 MiB | 1000:1000 | 0700 |
| `/home/zap/.mozilla/firefox/1337hack.zap-client-profile` | 4 MiB | 1000:1000 | 0700 |

Each mount requires rw/noexec/nosuid/nodev. Option order and equivalent byte/KiB/
MiB representations are supported. Duplicate, contradictory, unknown or missing
options fail closed. `Mounts` may be empty; if the engine supplies a tmpfs mirror,
its destinations must be approved and it must not report binds or volumes.

The existing network-none, read-only rootfs, UID/GID 1000, immutable identity,
ownership, local hostname, 1536 MiB memory, one CPU, PID limit 128, dropped
capabilities, no-new-privileges and no-published-port requirements remain.
HostConfig binds, structured mounts and volumes-from are rejected, as are binds,
volumes or Docker socket exposure in the native Mounts list. This check does not
declare ZAP initialized; API and initialization gates still run afterward.

`test/fixtures/zap-diagnostic-inspection-712c7658.json` is a sanitized subset of
the actual saved native inspection, with a source SHA-256. Command/environment
fields and unrelated native fields were omitted; retained values are unchanged.
The original three-mount fixture correctly fails the newly required profile
mount. Tests explicitly add the proposed fourth mount as mocked configuration;
they do not claim it was present in the prior real inspection.
Portable tests reproduce the legacy failure and exercise the corrected validator:

```bash
DAST_ACTIVE_ENABLED=false PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s backend/test -p zap_diagnostic_inspection_test.py -v
DAST_ACTIVE_ENABLED=false node --test backend/test/zap-diagnostic-inspection.test.js
```

The actual corrected temporary diagnostic was also replayed with every
`subprocess.run` replaced and evidence writes redirected into temporary test
directories. Four full mocked sequences cover valid/missing-rule initialization,
valid/complete initialization, invalid tmpfs capacity and unexpected host binds.
Both valid sequences reached the native measurement stage; invalid sequences
stopped before measurements. Every sequence exercised ownership-safe cleanup,
one mocked import and one mocked container creation, with zero real external
commands. The actual embedded Python payloads compiled; the storage/policy/heap
payload also ran against a mocked filesystem, including NUL-delimited Java
arguments and real XML parsing. Replay evidence is retained at
`/tmp/cs-zap-tmpfs-offline-replay-712c7658.json`.

No further inspection-shape mismatch was found before measurements in this
replay. Actual storage use, add-on loading, scanner IDs and API behavior remain
unverified. A new live diagnostic requires separate approval and fresh preflight;
the old approval and old snapshots must not be reused as authorization/readiness.
