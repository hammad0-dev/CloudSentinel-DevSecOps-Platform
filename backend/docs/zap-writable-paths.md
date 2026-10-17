# Firefox profile, Java preferences and listener readiness

This is source/offline preparation. The verified image, archive and seven-add-on
selection are unchanged; no container, image import or scan ran for this change.

## Genuine evidence and scope

`cs-zap-runtime-55yhezqx/initialization-logs.json` confirms one critical writable
path failure: `ExtensionClientIntegration` could not create
`/home/zap/.mozilla/firefox/1337hack.zap-client-profile/extension-preferences.json`
on the read-only rootfs. Java warned that its user preferences directory could
not be created and preferences were unusable. No other writable-path failure
was found in that complete retained startup log. The previous storage/policy
fix worked: 174.9 MiB used, 81.1 MiB free and valid policy XML.

The authentic required dependency closure for ascanrules, Automation, Network,
Reports, Common Library, OAST and Database does not declare the Firefox client
add-on. The approved plans use traditional spider/Active Scan jobs, not client
spider jobs. This is not proof that disabling an inherited extension is safe;
the correction leaves the client installed and enabled.

Read-only inspection of the saved verified image shows the profile directory
contains exactly one regular file: `firefox-extension-preferences.json`, 101
bytes, SHA-256 `c06f1d12e7cfb8f12158d6ac4d5541c01664b9d62892d1b0382ea30df2c73f54`.
The sibling `profiles.ini` remains outside the profile mount. A fresh empty
tmpfs would mask the seed file, so startup must restore its exact audited bytes
before ZAP initializes. No host bind or image change is needed.

The pinned image's Java 17 `java.prefs.jmod` was inspected offline.
`FileSystemPreferences$1.run()` gets `java.util.prefs.userRoot`, falls back to
`user.home`, then appends `.java/.userPrefs`. Class SHA-256 is
`928e31e0f738d8e9ce7ab5cead839a2bdc147a02102c578eba636202a281b479`.
The prior default is consistent with `/home/zap/.java/.userPrefs`, but the actual
prior JVM property was not captured, so that effective default was not directly
observed. The new explicit property removes this uncertainty. An additional
host-only Java 21 offline test confirmed the property writes into the selected
private prefix; it is not a replacement for pinned-container validation.

## Minimal configuration

`config/zap-writable-paths.json` records the evidence and exact configuration:

* Add only the profile directory as a 4 MiB rw/noexec/nosuid/nodev tmpfs, UID/GID
  1000, mode 0700. The inherited seed and generated preference JSON are small;
  4 MiB is an initial bounded allowance, not a runtime-proven capacity.
* Restore the seed with isolated Python, verified base64/SHA-256, O_EXCL,
  O_NOFOLLOW and mode 0600. Reject stale files, symlinks, wrong directory ownership
  or mode. Production also verifies the written SHA-256 before ZAP execution.
* Securely seed the launcher-supported `.ZAP_JVM.properties` first line with
  `-Xmx512m -Djava.util.prefs.userRoot=/home/zap/.ZAP`. The pinned launcher
  consumes this before `-jar`; standalone `-D` arguments would instead reach ZAP.
  Do not supply a separate `-Xmx` argument that overrides the properties line.
  Java creates its preferences
  at `/home/zap/.ZAP/.java/.userPrefs`, within the existing bounded home tmpfs.
  No additional Java writable mount and no warning suppression are introduced.
* Keep home 256 MiB, diagnostic `/tmp` and `/zap/wrk` 64 MiB each, memory 1536 MiB,
  heap 512 MiB and all other isolation restrictions. Total diagnostic tmpfs caps
  are 388 MiB; production caps are 516 MiB. These leave 636/508 MiB respectively
  for native/process memory beyond the maximum Java heap.

The mount path is an actual existing directory; its syntax uses the same Docker
tmpfs options already verified in real runs. Source validators enforce exact
paths, capacities and ownership. Actual Docker acceptance of this new fourth
mount and successful initialization still require an approved runtime attempt.

## Listeners and fail-closed observations

The prior log also showed OAST's callback listening on `0.0.0.0`. The selected
OAST 0.24.0 `CallbackParam.class` confirms the supported property
`oast.callback.localaddr`, default `0.0.0.0`. Pin it explicitly to `127.0.0.1`;
do not disable the required OAST dependency or ignore its wildcard listener.

`scripts/zap_writable_runtime.py` strictly parses both `/proc/net/tcp` and
`/proc/net/tcp6`. On the verified amd64 Linux runtime, IPv6 words use native
little-endian encoding. IPv4-mapped IPv6 loopback is decoded from actual socket
bytes and normalized to its IPv4 address; the original native value is retained.
IPv4 loopback and `::1` are accepted. Missing, truncated, malformed or ambiguous
tables block readiness. Any TCP LISTEN socket on a non-loopback address blocks,
even if it is not the API port; at least one observed API listener on port 8090
is required. This is TCP socket-table evidence, not packet-level or UDP testing.

Readiness additionally requires measured profile capacity, UID/GID/mode,
writability and seed digest, and the actual Java preferences root argument and
owned writable effective directory. The complete error-free initialization log,
all selected add-on versions, all seven scanner IDs, valid default policy and
absence of ENOSPC remain mandatory. Genuine profile/preferences failures remain
failures; no regex hides or downgrades them. Production capabilities remain null.

The prepared diagnostic source at `/tmp/cs-zap-runtime-55yhezqx/execute.py` now
uses the shared profile bootstrap, the new mount/property and the dual-stack
observer. It is preparation only: the consumed approval, identity and old
preflight files must not be reused to execute it. A new approved attempt needs
a fresh owner/evidence directory and safety preflight. No new live result is
asserted by these source changes.
