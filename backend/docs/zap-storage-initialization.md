# ZAP storage and initialization readiness

This is an offline correction. No runtime readiness or new capability is asserted.
Use the existing offline-assembled image and the unchanged seven-add-on selection.

## Confirmed evidence

The retained `cs-zap-import-hz3v5mq2` log reports failed installation writes under
`/home/zap/.ZAP` at approximately 3924–3927 ms: HUD tutorial resources, the Fuzz
`jbrofuzz/fuzzers.jbrf` data file, licenses and script templates failed with
`No space left on device`. It later reports configuration-save failures and,
at 11839 ms, a default-policy XML parsing failure with `Premature end of file`.
This order is confirmed; no raw default-policy file was retained, so its precise
length and the causal link between exhaustion and truncation cannot be proven.

Read-only analysis of the saved local base-image archives found 41,673,535 bytes
(39.74 MiB) across 292 declared installation files, using the newest present
archive per add-on; all declared file entries were found. This is a payload
estimate for the retained inherited add-ons, not a measurement of tmpfs usage.
WebDriver alone declares 33,124,496 bytes (31.59 MiB). Filesystem block/inode
overhead, logs, generated configuration, policies and databases are additional.
The original 32 MiB mount was therefore insufficient even for declared payload.
The evidence does not establish which write consumed the final available byte.

## Bounded storage plan

The shared source contract is `services/zapInitialization.js`:

* `/home/zap/.ZAP`: 256 MiB, rw/noexec/nosuid/nodev, UID/GID 1000, mode 0700.
* Network-disabled diagnostic `/tmp` and `/zap/wrk`: retain 64 MiB each with the
  existing protections; no retained error establishes a shortage on these paths.
* Production `/tmp`: retain its existing 256 MiB cap for reports and temporary
  data. Its `/zap/wrk` remains the existing read-only artifact mount; no new host
  mount is added.
* Java: supply `-Xmx512m` through the launcher-supported `.ZAP_JVM.properties`
  together with the preferences-root property (see `zap-writable-paths.md`).
  Offline inspection of the pinned `zap.sh` shows it accepts `-Xmx*` and forwards
  that value to Java. Its automatic heap calculation may consult host memory on
  cgroup v2, so it must not determine this bounded diagnostic's heap budget.
* Container memory: 1536 MiB. Even a conservative combined 576 MiB tmpfs cap and
  512 MiB heap leave 448 MiB for native JVM memory, processes and other charged
  pages. Actual diagnostic tmpfs caps total 384 MiB; production totals 512 MiB.

The later profile/preferences correction adds one 4 MiB Firefox-profile tmpfs,
preserves its 101-byte inherited seed file, and redirects Java user preferences
inside the existing ZAP home. See `zap-writable-paths.md`. Current combined caps
are therefore 388 MiB for the diagnostic and 516 MiB for production, leaving
636 MiB and 508 MiB respectively beyond a 512 MiB heap under the 1536 MiB limit.
The earlier 384/512 MiB totals above describe the pre-profile configuration.

256 MiB provides over six times the declared installation payload; 512 MiB is
not initially justified by the available footprint and would consume more memory
headroom. Neither size is claimed sufficient by real testing. A future approved
diagnostic must observe actual capacity, usage/free space, writable ownership and
effective Java heap limits. The gate requires at least 32 MiB free after complete
initialization. If space or memory is insufficient, stop rather than silently
expanding writable storage.

Use `diagnosticStorageArguments()` with the existing hardened diagnostic
arguments. It keeps `--network none`, read-only rootfs, user 1000:1000 and bounded
tmpfs mounts; retain dropped capabilities, no-new-privileges, CPU/PID limits,
local hostname mapping, no published ports, no host mounts and private API key.
Seed the verified JVM properties file before daemon invocation. The production command uses
`-dir /home/zap/.ZAP` rather than initializing add-on state inside `/tmp/zap-*`.

## Readiness boundary

Before treating any policy/rate/report probe as eligible, a future approved
diagnostic must collect a complete, bounded startup log from process start,
not just its last 500 lines, and use `assertInitialized()` on genuine observations:

1. Bind evidence to the independently inspected imported image identity. Version
   2.17.0, extension initialization and loopback-listening records must be present.
2. Measure storage and effective heap limits; confirm UID/GID, permissions,
   writability, read-only rootfs and post-initialization free space.
3. Read the complete actual `policies/Default Policy.policy`, parse XML using a
   real XML parser, record its byte count/SHA-256 and require successful loading
   through the genuine policy API. A zero-length or unparsable file blocks.
4. Observe all seven selected installed versions and their loaded identities;
   `INSTALLED` or an archive alone does not prove active rules were registered.
5. Require all seven approved SQLi/XSS IDs from the actual scanner inventory.
6. Any storage exhaustion, installation/initialization error, malformed policy,
   missing output or truncated diagnostics blocks admission. Errors expose codes,
   not raw logs or credentials. Keep native evidence owner-restricted and redact
   API keys before storing diagnostic text.

The production catalog additionally requires this initialization evidence in
`zap.capabilities.initialization`. The existing catalog still has capabilities
null and stays blocked. Boolean fields in mocked tests are explicitly offline
fixtures; never fill this record with assumptions or version-only readiness.
Post-command stdout and stderr are both checked for initialization errors even
when the command exits zero. These checks supplement the existing containment,
authorization, job completion, timeout, cancellation and reporting requirements.

A new network-disabled diagnostic is technically justified to validate the
corrected storage budget and genuine loaded rules. It requires separate explicit
runtime authorization. No scan or Module 2 execution is authorized by this file.
