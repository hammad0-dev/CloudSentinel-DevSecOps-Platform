# Direct TCP evidence contract

The `c19b-f2-a83d7c1e` report retained Docker exec exit 1 but no native nc
stdout/stderr or failed predicates. Therefore it cannot establish whether nc
reported unreachable, timeout, tool failure, empty output, or whether a route
proof was missing/stale. The original failure cannot be reconstructed.

The production command is now `nc -n -v -z -w 5 <verified-fixture-ip> <port>` with
separate argv, no shell, and a lifecycle-verified client. The genuine pinned-image
help capture in `backend/test/fixtures/nginx-nc-help-41d2bf36.json` confirms `-n`
(no DNS) and `-v` (verbose). It does not verify the actual verbose failure format.
DockerAdapter already retains failed
command output privately; the client now captures bounded evidence for all TCP
outcomes, including adapter errors, before that evidence leaves trusted execution.

DENY requires actual exit 1, clean bounded native output, empty stdout, explicit
network-unreachable stderr without timeout/refusal/DNS/setup ambiguity, and an
issued, current route proof matching the inspected client network/IP/MAC and
placing the attempted destination outside its sole connected subnet. Exit 1
alone remains INCONCLUSIVE. Successful exit 0 with clean empty output is ALLOW
(a containment failure). Malformed/NUL/oversized output fails closed.

On an inconclusive or unexpectedly allowed TCP observation, runtimeObservation saves an owner-restricted
0700 directory with a 0600 `tcp.json`. It retains bounded, redacted native text;
the artifact is diagnostic evidence, not executable/configuration staging.
Public failure reports expose only the command/destination, actual exit code,
adapter classification, output category/size/hash, each denial predicate and
failed predicate names, plus the private artifact path. No raw text is public.
Absent output is marked MISSING rather than reconstructed from an expected error.

Lifecycle cleanup remains in both the provisioning error path and runner finally.
The native same-socket CONNECT verifier and delivery code are unchanged. A future
separately approved run must collect the new artifact to resolve the original
uncertainty. No runtime fix or containment PASS is asserted by these source tests.

## Evidence limits and alternative mechanisms

The successful `routeMatches` predicate means the issued, fresh main-table and
interface observations agree with inspected network/IP/MAC identity and place
the fixture outside the sole observed connected subnet. Within that observed
table there is no eligible direct route (A), rather than an explicit prohibit
route (B). The capture does not enumerate every routing-policy rule/table or
perform a kernel destination lookup, so the effective mechanism remains
undetermined (C). Neither this predicate nor silent nc exit 1 proves isolation.

BusyBox help does not establish support/output for a destination-specific
`ip route get` lookup. Do not introduce an unverified command or invent its
output. The audited CONNECT client uses a transaction-bound socket, but maps
connect()/SO_ERROR failures to generic CONNECT_FAILED; it does not expose errno
or provide a TCP-only mode. It cannot currently distinguish ENETUNREACH from
ECONNREFUSED/timeout for this task and remains unchanged.

The narrow correction requests nc's already-supported verbose numeric mode,
retains real output through the existing private diagnostic path, and leaves
the denial contract unchanged. A separately approved targeted runtime diagnostic
must establish whether this emits an explicit network-unreachable result for the
same inspected destination. Unknown verbose formats and silent failures remain
INCONCLUSIVE; no presumed output is added as a genuine fixture. If verbose mode
cannot provide this, the missing capability is an audited TCP-only errno/SO_ERROR
observer (or independently validated kernel destination lookup), requiring
separate implementation/validation rather than weakening the verifier.
