# Native CONNECT delivery: acceptance-only opt-in

Default full acceptance and default diagnostics still use curl. Native delivery
requires `CS_ACCEPT_NATIVE_CONNECT=true`; both full acceptance (default or
`CS_ACCEPT_MODE=full`) and `CS_ACCEPT_MODE=connect-diagnostic` support it.
Unknown flag values fail before provisioning. Native
diagnostics cannot issue full-containment READY/PASS or runtimeReady evidence.
Full mode retains every mandatory probe in its original order and substitutes
only CONNECT. A native DENY alone cannot establish full containment; all other
probes and independently collected runtime preconditions must also pass.

## Secure artifact

The source pin is
`b2646e230e66286d00fc346b80cf605bc1bbda1c8d965712bb0d8e033714bc2b`;
the binary pin is
`278ca7f3071fbf9e253b5f5bed67325e2e7fa315ace823b6675c269112271f94`.
The only accepted binary source is the fixed audited file
`/tmp/cloudsentinel-connect-peer-build-lxZg6cbw/connect-peer`. No request,
environment or CLI path override exists. Missing/changed files fail before
network allocation; there is no rebuild/download fallback.

Source and binary reads reject symlinks, foreign owners, hard links and changed
inode/device/owner/mode/size. Descriptors use O_NOFOLLOW; reads are bounded to
2 MiB plus one growth-detection byte. Parent directories must be real and owned
by root/current UID. ELF64 little-endian ET_DYN/x86-64/version checks and the
exact audited hash enforce executable identity. Non-x64 hosts fail closed.

A fresh scan-owned 0700 directory holds one exclusively created 0500 executable.
Frozen artifacts are authorized by a private WeakMap with device/inode records;
cloned objects, arbitrary paths and stale artifacts cannot authorize use/removal.
Cleanup unlinks only the known owned file and removes an empty owned directory.
It rejects substituted paths or unknown contents and handles partial deletion.

## Mount, transaction and cleanup

The acceptance client receives one read-only file mount at
`/opt/cloudsentinel/connect-peer` and runs as the host artifact UID/GID. Existing
read-only root filesystem, dropped capabilities, no-new-privileges, pinned image,
no published ports and scanner-only owned network remain. Docker inspection must
show exactly that mount (no overlaps/other mounts), user and security settings.
Host artifact ownership/hash and the container-visible SHA-256 are rechecked
before native invocation.

Normal container/network, route/interface and active-policy preconditions run
first. Only CONNECT changes implementation. The native verifier independently
inspects gateway/network IDs and compares actual same-socket getpeername() data,
authority, complete headers and explicit rejection with the inspected endpoint.
Missing/malformed/contradictory output remains inconclusive. Unexpected complete
tunnels are ALLOW, never DENY. Other probes and native C source/binary are
unchanged. The owner-restricted diagnostic file retains bounded native fields.

Staging is tracked before Docker allocation. Runner finally cleanup removes
only owned resources. Binary removal follows confirmed client removal; a
remaining client retains the binary and reports CLIENT_STILL_PRESENT. Diagnostic
JSON is intentionally retained as evidence, unlike staged runtime artifacts.

## Future separately approved command (not executed)

```bash
cd /home/hammad/CloudSentinel
DAST_ACTIVE_ENABLED=false \
CS_ACCEPT_MODE=connect-diagnostic \
CS_ACCEPT_NATIVE_CONNECT=true \
CS_ACCEPT_PROJECT=c19b \
CS_ACCEPT_EXECUTION=native1 \
CS_ACCEPT_SCAN=c19b-native-9b61d2a7 \
CS_ACCEPT_HOST=c19b-fixture-9b61d2a7.test \
CS_ACCEPT_PORT=18080 \
node backend/scripts/dast-acceptance.js \
  > /tmp/c19b-native-9b61d2a7.stdout.json \
  2> /tmp/c19b-native-9b61d2a7.stderr.json
```

Fresh health, images/architecture, hashes, ownership, inventory, allocation and
identity uniqueness checks plus explicit approval are required. Actual bind
delivery/execution and real CONNECT remain unverified. The fixed audited /tmp
artifact must still exist under the same UID at preflight.

## Files changed

- Services: nativeConnectArtifact.js, dockerAdapter.js, dastAcceptanceClient.js,
  sameSocketConnect.js, dastGateway.js, runtimeObservation.js, connectDiagnostic.js.
- Runner: scripts/dast-acceptance.js.
- Tests: native-connect-artifact.test.js, same-socket-connect.test.js,
  gateway-integration.test.js, dast-acceptance-runner.test.js,
  docker-adapter.test.js, helpers/runtimeDocker.js.
- Documentation: this file and c19b-native-connect-client.md.

The adapter sanitization test now excludes random UUIDs from literal hexadecimal
secret checks, avoiding coincidental UUID substrings while retaining assertions
on every diagnostic payload field. All Docker operations in tests are mocked;
native unit tests replace socket syscalls and open no network connections.
