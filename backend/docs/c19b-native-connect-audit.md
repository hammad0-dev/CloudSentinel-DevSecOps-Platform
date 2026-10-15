# Native CONNECT client: offline compile and audit

Toolchain: GCC (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0; GNU Make 4.3;
target x86_64-linux-gnu. No package installation, Docker operation or live socket
probe occurred. The production curl verifier and persistent runner are unchanged.

## Findings and corrections

- getpeername(), send(), recv(), close() all use the same descriptor returned by
  socket()/connect(). Reported peer fields come from the kernel sockaddr, never
  the configured address. A peer mismatch aborts before sending CONNECT.
- Nonblocking I/O uses a single monotonic 5-second deadline. A deadline recheck
  after poll now rejects readiness delivered after expiration. Partial I/O,
  EINTR/EAGAIN retries, failed asynchronous connect, peer failure, EOF, timeout
  and descriptor cleanup are covered by syscall-mocked tests.
- The verifier previously could label an incomplete parsed HTTP 200 as ALLOW.
  Native output now separately records complete header validity; unexpected
  tunnels require coherent native exit/error/status, verified peer/authority,
  complete valid headers and no contradictory access-denied marker. Any stderr
  prevents a conclusive result. Malformed gateway addresses are rejected before
  invoking the experimental client.
- Existing authority validation prevents CRLF/argument injection. Header/body,
  line/name/count/output limits and duplicate-header/redirect rejection remain.
  No target/tunnel data is sent after CONNECT. Open descriptors are closed once
  on every transaction exit; close is not retried against a potentially reused
  Linux descriptor.

## Offline validation

The build recipe compiles both client and unit executable with C11, strict
warnings as errors (including format, conversion, shadow and prototype checks),
stack protector, stack-clash protection, FORTIFY, static PIE, RELRO, immediate
binding, non-executable stack and no linker build ID.

Native syscall tests replace every socket-related call; they open no real
sockets. Tests cover partial I/O, EINTR/EAGAIN, connection/peer/send/recv/poll
failures, mismatch, EOF, timeout, malformed/duplicate/oversized/excessive headers,
injection, unexpected tunnels and 10,000 deterministic bounded parser inputs.
The same harness passed ASan/UBSan with leak detection. GCC -fanalyzer emitted
no warnings. Four production-binary offline CLI rejection cases (no arguments,
invalid port, injected authority and invalid IP) passed without reaching socket().

Two clean builds with the same source/toolchain produced byte-identical clients.
`file`/`readelf` confirm ELF64 x86-64 static PIE, no PT_INTERP or DT_NEEDED entries,
GNU_RELRO, BIND_NOW and non-executable GNU_STACK. This verifies static linking
rather than inferring it from a compiler flag. No ldd execution was needed.

## Retained artifacts

Primary directory: `/tmp/cloudsentinel-connect-peer-build-lxZg6cbw`

Second build: `/tmp/cloudsentinel-connect-peer-build-ksNv3bo7`

Each includes connect-peer, native-unit, native-tests.log, binary.sha256,
source.sha256, toolchain.txt and flags.txt. The primary directory additionally
contains native-unit-sanitized and the analyzer object. Complete tool output,
ELF details, offline CLI results and checks are recorded in
`/tmp/c19b-native-audit-final-results.json`.

Client source SHA-256:
`b2646e230e66286d00fc346b80cf605bc1bbda1c8d965712bb0d8e033714bc2b`

Client binary SHA-256:
`278ca7f3071fbf9e253b5f5bed67325e2e7fa315ace823b6675c269112271f94`

These hashes apply to the audited C source and binary, not the documentation.
Reproducibility has been shown locally, not across arbitrary toolchains.

## Remaining gates

Runtime socket behavior and execution inside the pinned Alpine container remain
untested. The experimental verifier is not imported by production observation.
Before runtime approval, implement/test lifecycle-owned binary staging with
source/build/hash verification, a single read-only mount, observed mount/hash
verification, and ownership-scoped artifact cleanup. Use a distinct native
diagnostic path that cannot grant full containment readiness. Fresh health,
inventory and identity checks plus explicit approval are required before any
Docker delivery or real CONNECT transaction.
