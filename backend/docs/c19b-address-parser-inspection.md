# C1.9B address parser inspection

One disposable inspection container used the existing pinned Nginx image
`nginx:1.27.5-alpine@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8`.
It used network none, a read-only root filesystem, all capabilities dropped,
no-new-privileges, no mounts and no published ports, with image pulls disabled.
No lifecycle, gateway/scanner network or containment probe was invoked.

`ip address show` returned exit 0, empty stderr, and 295 stdout bytes in six
nonempty lines: a loopback header with qdisc/state/qlen, link/loopback and zero
MAC/broadcast, IPv4 127.0.0.1/8 scope host lo, a lifetime line, IPv6 ::1/128
scope host, and a lifetime line. The new fixture preserves this output exactly;
there are no non-loopback addresses to redact.

Full inspection evidence: `/tmp/c19b-addr-3e5d2845.json`. Removal rechecked the
exact container ID and unique inspection ownership label. Before/after Docker
container and network ID sets match. The additional read-only BusyBox string
inspection found lifetime format strings; it did not establish any new
Ethernet interface output grammar.

The current parser already accepts this genuine capture. Therefore no
runtime-format mismatch is reproduced or confirmed by this inspection. The
earlier attached client's 468-byte, eight-line output was not saved. Its
`UNRECOGNIZED_OR_INCOMPLETE_NATIVE_ADDRESS_FORMAT` error remains unresolved;
network-none cannot expose its Ethernet header/link/address representation.
No attached-interface fixture has been represented as a genuine capture.

A separate confirmed completeness defect was corrected: the parser formerly
allowed an address to omit its lifetime line at EOF, before another address,
or before the next interface header. It now requires the complete lifetime
pair emitted by the pinned BusyBox utility. Link-layer addresses now require
exactly six hexadecimal octets rather than any 17 characters from a hex/colon
character class. Accepted route/header/address formats are otherwise unchanged.

Regression coverage includes the genuine loopback output, incomplete lifetimes,
malformed IPv6/MACs, interface-name disagreement, modeled missing IPv4 or eth0,
extra interfaces, global IPv6, endpoint IP/MAC conflicts and unknown lines.
The genuine loopback capture parses successfully but fails containment checks:
it contains IPv6 and lacks the required owned eth0 endpoint. Existing default
route and IPv6 bypass rejection remain in place.

Status: PARTIAL. The inspected output is supported and the completeness defect
is fixed; the original runtime parser failure is not claimed resolved. Actual
attached-interface text remains necessary to identify its exact grammar issue.
No further live attempt was made.
