# Experimental same-socket CONNECT client

Default production curl verification is unchanged. Native delivery is integrated
behind an explicit acceptance-only opt-in for full or diagnostic mode; see
`c19b-native-connect-delivery.md`. It cannot produce runtimeReady evidence and
always labels its result EXPERIMENTAL_NOT_ACCEPTANCE/fullContainment:false.

## Native protocol

`connect-peer NUMERIC_IPV4 DECIMAL_PORT HOST:PORT` opens one nonblocking Linux
IPv4 socket, completes connect(), obtains the kernel peer with getpeername(),
and sends/receives the CONNECT exchange on that same descriptor. A different
observed peer aborts before sending the request. No address is substituted into
the observed peer fields. There is no DNS lookup, redirect handling, TLS or
target data after CONNECT. Every opened socket is closed on success/error.

The output is a bounded JSON record with schemaVersion, peerIp, peerPort,
requestedAuthority, responseStatus, connected, squidServer, accessDenied,
headersValid, complete and a fixed error code. Native exit 0 means a complete Squid rejection;
1 means an incomplete/error/contradictory transaction; 2 means invalid CLI args.
An unexpected CONNECT 200 is recorded but never treated as DENY.

Limits: one 5-second monotonic transaction deadline, 16 KiB response headers,
64 headers, 1024 bytes per line, 127 bytes per header name, 253-byte host, and
bounded request/output. poll() bounds nonblocking reads/writes, including EINTR
and EAGAIN retries. Partial sends/receives and EOF are handled. Header names,
CRLF framing, duplicate headers and authority syntax are validated. A complete
403 header block must contain exactly one Squid Server/version and exactly one
ERR_ACCESS_DENIED 0 marker, without Location or contradictory headers. Response
bodies are not needed to establish explicit proxy rejection and are not read
after the header terminator. Raw response/header values are never printed.

## JavaScript boundary

`sameSocketConnect.observeSameSocketConnect` uses the existing lifecycle-owned
client verification and independently inspects both owned networks and the
gateway ID, image, ownership, security and memberships. Only then may it invoke
the fixed executable path `/opt/cloudsentinel/connect-peer` through the existing
Docker adapter, passing separately validated argv. Output is bounded and parsed
strictly; observed peer IP/port, authority, status and rejection flags must agree
with independent inspection. This module is deliberately not production wired.

## Build and unit validation

The initial source-only pass had no C compiler. After the user installed the
toolchain, GCC 13.3.0 compiled the client and native syscall tests successfully.
Strict warnings, static analysis, ASan/UBSan and two-build reproducibility checks
passed. See `c19b-native-connect-audit.md` for exact artifacts and limitations.
The optional compiler skip remains for environments without a C toolchain.

`sh backend/scripts/build-connect-peer.sh` is a local-only static Linux build
recipe. It builds and runs the syscall-mocked unit executable before retaining
artifacts. With a suitable existing toolchain/static libc it creates a private
temporary build directory, a 0500 executable, binary SHA-256, source SHA-256,
compiler version and flags. SOURCE_DATE_EPOCH, locale, path mapping and omitted
build IDs reduce variability. Reproducibility must be demonstrated by two clean
builds with identical source/toolchain/libc and matching binary hashes; it has
been established for two clean builds with the audited local toolchain. The
script never installs or downloads anything.

`connect-peer-test.c` replaces socket/connect/getpeername/getsockopt/poll/send/
recv/close with fakes. Its tests make no network calls, and cover same-descriptor
use, partial I/O, EINTR, deadlines, peer mismatch, malformed/incomplete/oversized
headers, duplicate evidence, injection and unexpected tunnel success. Node
tests cover the experimental output contract, ownership checks and cleanup.

## Delivery design

After independent compilation, tests and binary review, stage the exact approved
static Linux executable in a unique lifecycle-owned 0700 directory. Verify owner,
regular-file type/no symlink, architecture, source/build manifest and recorded
binary SHA-256; use mode 0500 for the existing container UID. Mount that exact
file read-only at `/opt/cloudsentinel/connect-peer` on the lifecycle client,
with no Docker socket, privileges or additional network. Verify the observed
mount and executable hash before invoking it. Do not mount an entire host tree.

Container removal must precede ownership-scoped staged-binary cleanup, with
partial provisioning tracked just like fixture/policy artifacts. Source-only
lifecycle staging/mounting is now implemented and mock-tested as described in
`c19b-native-connect-delivery.md`; actual Docker delivery has not been executed.
The existing pinned images need not be replaced for the static executable.

Native offline validation and delivery mock tests are complete. Fresh preflight
and explicit approval remain required before testing the mount, executable and
real rejection in the pinned container. Native execution remains diagnostic-only.
No Docker execution, image build or live probe occurred during integration.
