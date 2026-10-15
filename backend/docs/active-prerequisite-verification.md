# Active prerequisite readiness

Source-only changes add the fixture Dockerfile/build requirements, /health and
per-request SQLite files in /tmp. No image/base digest has been invented, no image
was built, and the runtime artifact catalog remains unchanged and blocked. Future
runtime must mount bounded /tmp tmpfs and keep UID/GID 10001, rootfs readonly,
no host ports, no external connections and lifecycle-owned isolated networks.

activeSquidPolicy is an injectable policyService for SecureGatewayLifecycle. It
uses the existing private policy staging/digest/cleanup implementation with the
Active profile. Exact hostname/IP/18080, HTTP, GET/POST and only /test/sqli or
/test/xss (optional query) are required. Other origins, paths, CONNECT and HTTPS
are denied. A cross-origin redirect therefore cannot access its next origin;
the current vulnerable fixture itself never redirects. The actual scanner cannot
start unless freshly inspected gateway config bytes match this canonical profile.
Default C1.9B policy bytes and containment controls remain unchanged.

ActiveZapRuntime's capability contract now explicitly requires evidenced API
loopback binding/authentication, spider and active rate control, single worker,
exact scope, verified job completion/timeout/cancellation, report format and
evidence fingerprint. Scanner command construction binds API to loopback with a
fresh private key. These requirements do not claim those capabilities exist:
current pinned-image records establish metadata only and cannot pass the contract.

Later separately authorized checks must capture pinned ZAP version/add-on inventory,
the seven approved rule IDs and their SQLi/XSS mappings, named Automation Framework
policy/job support, proxy-chain options, API bind/key enforcement, measured rate
including spider traffic, exact path/redirect scope, positive completion versus
duration-limit/partial report, cancellation and report export. Confirm required
namespace/hash tools in the actual scanner image. Fixture build requires approved
Python base identity/capabilities, reproducibility evidence, final digest and
independent health/route/ownership checks. No probe is authorized by this document.

Migration 012 now associates execution/project through a composite FK and includes
CLEANUP_FAILED. Migration 013 associates targets and grants with the same project
and execution through composite FKs. Atomic conditional UPDATE consumption, role,
owner, expiry and replay predicates remain. Tests inspect schema/query contracts
offline; no live SQL migration or actual PostgreSQL concurrent transaction test
occurred. Both migrations remain unapplied.

End-to-end tests invoke the genuine Module 2 orchestrator and Active stage with
mocked scanner/database/stage boundaries. Disabled behavior, order, findings,
cancellation, containment failure, cleanup failure and Project 17 blocking are
verified. They are not real Module 2 executions or runtime evidence.

Remaining blockers: verified Python base and built fixture digest; actual ZAP
capability/job semantics evidence; production vulnerable-fixture preparation and
registration in the live lifecycle; migration/operator enrollment approval; then
independent new scanner containment verification before any Active end-to-end scan.
