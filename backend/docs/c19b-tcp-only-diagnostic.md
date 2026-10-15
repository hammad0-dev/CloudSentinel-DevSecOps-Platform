# TCP-only diagnostic

`CS_ACCEPT_MODE=tcp-diagnostic` reuses genuine SecureGatewayLifecycle provisioning,
verified fixture IPv4, isolated owned networks, inspected client/gateway/network
identities, namespace route/interface validation and active Squid policy checks.
It then runs only `nc -n -v -z -w 5 <verified-fixture-ip> <fixture-port>` through
the trusted client. No HTTP or CONNECT probes execute. Native CONNECT opt-in is
unnecessary. Full and CONNECT-only behavior remain unchanged.

Every completed diagnostic returns `diagnosticOnly:true`, `fullContainment:false`
and `DIAGNOSTIC_COMPLETE`; it never issues runtimeReady. CLI exit 0 means complete
diagnostic DENY only, exit 2 means ALLOW/INCONCLUSIVE/ERROR, exit 1 means operational
or cleanup failure. Precondition failures stop before nc. Runner finally and
lifecycle failure cleanup retain normal ownership checks.

The retained 0700 directory / 0600 tcp.json contains bounded redacted native
output, actual exit/destination/command, categories and predicate fingerprints,
inspected client ID, network ID/membership/MAC, verified fixture address and
parsed plus native IPv4/IPv6 route/interface snapshots. Context values are bounded
by depth, count, individual size and total 64 KiB; excessive evidence fails rather
than silently claiming completeness. Public results contain only the existing
safe TCP summary and private artifact path. Diagnostic artifacts are intentionally
retained; executable/configuration staging is cleaned.

Main-table route absence is recorded separately from effective kernel decision
UNKNOWN; no explicit kernel prohibition is invented. DENY requires explicit
network-unreachable output and all existing route/identity predicates. Silent
exit 1, refusal, timeout, missing/malformed output and tool errors fail closed.
Unexpected direct success remains ALLOW. Native CONNECT code is unchanged.

Prepared future invocation (requires separate runtime approval and fresh preflight):

```sh
DAST_ACTIVE_ENABLED=false \
CS_ACCEPT_MODE=tcp-diagnostic \
CS_ACCEPT_PROJECT=c19b \
CS_ACCEPT_EXECUTION=td1 \
CS_ACCEPT_SCAN=c19b-td-3626a897 \
CS_ACCEPT_HOST=c19b-fixture-3626a897.test \
CS_ACCEPT_PORT=18080 \
node backend/scripts/dast-acceptance.js
```
