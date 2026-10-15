# Full acceptance matrix and resource names

The failed `c19b` / `nfull1` / `c19b-nfull-20261015-a82f49c1`
identity generated a 68-character scanner network name. Inspectable names
are limited to 63 characters. Short existing names remain unchanged; longer
names now contain a 128-bit SHA-256 prefix over the complete identity tuple.
Full scan/project/execution/lifecycle identities remain in ownership labels.
Container names follow the same bounded scheme. The runner and lifecycle
validate all generated names before staging. Network roles must be unique;
observed network name collisions fail before creation. Docker create failure
never authorizes cleanup of a pre-existing object.

Full mode executes these named cases in order:

1. positive-fixture: proxied fixture `/health`, HTTP 200.
2. negative-proxy: unauthorized hostname policy denial.
3. negative-connect: explicit CONNECT rejection, native only on opt-in.
4. negative-direct-bypass: nc result corroborated by namespace isolation.
5. negative-redirect: observed cross-origin 302 followed by Squid 403.
6. negative-alternate-host: fixture numeric IP denied by hostname policy.
7. negative-port: fixture origin on the unauthorized port denied.
8. negative-public: numeric TEST-NET-2 destination `198.51.100.9:80`,
   requiring complete Squid 403/ERR_ACCESS_DENIED headers and observed proxy IP.
   This controlled nonprivate destination avoids requesting a third-party service.
9. negative-metadata: `169.254.169.254:80` with the same explicit policy evidence.
10. positive-same-redirect: observed fixture 302 to its own `/health`, exactly
    one redirect, matching final URL and HTTP 200 through the verified proxy.
11. negative-ipv6-bypass: structural namespace evidence from successful actual
    IPv6 route and interface-address commands: no IPv6 routes or addresses,
    only the expected inspected interfaces. This is not an IPv6 packet probe;
    unsupported BusyBox `nc -6` is never invoked. Unsafe or incomplete namespace
    evidence fails before connectivity probes.

DNS errors, timeouts, missing peers, malformed headers and incomplete redirect
chains cannot satisfy the new cases. All named cases must complete successfully;
mocked adapters and standalone diagnostics cannot issue runtime READY.

Prepared identity: project `c19b`, execution `f2`, scan `c19b-f2-a83d7c1e`,
fixture `c19b-fixture-a83d7c1e.test:18080`. Maximum generated name length is
52 characters (network lifecycle hash is always 12 hex digits).

No live execution is authorized by this document. Fresh safety preflight and
separate approval are required before running with `CS_ACCEPT_MODE=full` and
`CS_ACCEPT_NATIVE_CONNECT=true`. Real full containment remains unverified.
