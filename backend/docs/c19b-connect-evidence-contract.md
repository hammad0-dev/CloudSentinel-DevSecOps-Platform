# C1.9B CONNECT evidence contract

The real `/tmp/c19b-final-5a42086b.stderr.json` records curl exit 56, HTTP 000,
CONNECT 403, and an inconclusive CONNECT result. It does not record the remote
proxy address or response headers. These observations cannot be reconstructed.
There is no evidence that the real response contained complete trusted Squid
headers, or that its remote address matched the configured gateway.

The previous classifier already required HTTP 000 for rejected CONNECT. It also
required exactly three write-out fields, the configured proxy remote IP, one
ERR_ACCESS_DENIED marker and no setup/DNS/timeout ambiguity. The original report
does not distinguish which predicate failed. HTTP 000 was not incorrectly
treated as an absent destination response; a rejected tunnel never reaches the
destination HTTP server.

Confirmed defects: failed Docker commands flattened CR/LF and truncated output
to 4096 characters before consumers received it; the runner omitted CONNECT's
evidence predicates. Native output is now retained in a private WeakMap on the
adapter error, separate from sanitized enumerable diagnostics. Probe parsing can
read the original command streams. Forged errors have no private output record.

CONNECT now uses curl --verbose instead of --dump-header (other probes retain
their commands). This captures the actual CONNECT authority and Host request
header, response status/headers and terminating blank line without duplicating
response headers. The new classifier requires:

- An explicit expected DENY and a lifecycle-verified client.
- Independently inspected running gateway ID, owner, role, pinned image and
  scanner-network endpoint matching the configured proxy.
- Matching numeric remote proxy IP in the actual curl write-out.
- Exactly one matching CONNECT authority/Host, followed by a complete, well
  formed HTTP/1.x 403 response with one Squid Server header and one
  X-Squid-Error: ERR_ACCESS_DENIED 0 header, without a Location header.
- Actual curl exit 56, HTTP 000 and CONNECT 403, without ambiguous network,
  timeout, DNS, setup or contradictory connection-failure evidence.

An unexpected successful CONNECT remains ALLOW, so the observation's expected
DENY fails. No ambiguous error becomes a denial. M-DOWN, route and interface
validation are unchanged. Mocked adapters still cannot issue real containment
attestations.

The modeled connect-denied.json fixture is explicitly NOT a real runtime
capture. It exercises the contract without asserting headers absent from the
original evidence. Regressions cover missing/incomplete/conflicting headers,
wrong authority/proxy/expected outcome, statuses, successful tunnels, setup,
DNS, timeout/refusal errors, diagnostic sanitization and ownership-safe cleanup.

A separately approved runtime attempt must collect the complete curl verbose
CONNECT exchange and write-out from the real owned client, plus independently
inspected gateway/client identity. Failure reports now include each boolean
predicate and the stderr byte count/SHA-256. Raw header values are not serialized.
In particular, a missing remote IP or missing actual Squid Server/error header
must remain inconclusive; neither may be supplied from assumptions. The exact
original failed predicate remains unknown until this evidence is collected.

No Docker operations, containment attempts, source-time network requests,
service restarts or image downloads were performed during this repair.
