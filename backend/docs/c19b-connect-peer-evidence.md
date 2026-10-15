# CONNECT proxy peer evidence

The real c19b-conn-3345d93b report proves only that the old proxyPeerMatches
predicate was false. It omits native write-out and verbose text, retaining only
the latter's byte count and SHA-256. Therefore an empty remote_ip, wrong peer IP,
or malformed write-out cannot be distinguished retrospectively. No missing
address has been reconstructed or replaced with the configured proxy address.

The previous predicate required three write-out fields and an exact remote IP
match. The gateway endpoint was independently inspected on the scanner network,
and the real report confirms that gatewayIdentity matched. The failure is thus
in the write-out peer predicate, not evidence of a confirmed Docker ID mismatch.
Whether failed tunnel establishment left remote_ip empty is still unconfirmed.

The existing --verbose command can emit curl's client-side successful socket
connection record before the CONNECT request. Source-only parsing now accepts
the exact numeric form:

```text
* Connected to 172.30.25.3 (172.30.25.3) port 3128
```

An optional curl connection-number suffix ` (#0)` is recognized. The numeric
host and socket address must agree, the port must be 3128, and the record must
precede the request. These examples are modeled regression inputs, not captures
from the lost real output. Actual pinned-image formatting remains subject to a
separately authorized runtime observation; unknown formats fail closed.

This is a peer observation from the same trusted client curl process, independent
of the configured address and of proxy-supplied HTTP headers. It is not inferred
from a Trying message, CONNECT status, Squid error marker or Docker inventory.
Proxy headers have curl's `< ` prefix and cannot satisfy the anchored `* `
client connection record. Multiple/reordered/malformed connection records fail.

Matching remote_ip remains sufficient peer data when available. If it is
absent, exactly one matching successful socket record can supply peer evidence.
Any supplied wrong/malformed remote IP or contradictory socket IP/port blocks
denial, even if the other source matches. Gateway ID, network ID, pinned image,
ownership, running state and scanner-network IP remain independently required,
alongside all existing request/response/header/status checks. Unexpected allowed
tunnels remain ALLOW and contradict the expected DENY.

Public reports now separately include curlRemoteIpPresent, curlRemoteIpMatches,
observedPeerSource, observedPeerMatches, expectedGatewayNetworkIdMatches and
expectedGatewayContainerIdMatches. peerEvidenceStatus distinguishes MATCH,
MISSING, MISMATCH and MALFORMED. Only bounded enums, booleans, counts and hashes
are serialized, with no raw stderr or untrusted peer strings.

Another runtime attempt requires separate approval and fresh preflight. It must
collect a matching native write-out IP or the recognized successful client-side
socket record. If neither exists, the outcome remains INCONCLUSIVE. No Docker
operations, containment probes or service changes occurred in this repair.
