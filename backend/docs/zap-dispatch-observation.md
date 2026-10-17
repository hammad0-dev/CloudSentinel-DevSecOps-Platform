ZAP dispatch/admission evidence — source analysis and blocked collector

Confirmed path: execution-owned ZAP -> owned Squid :3128 -> exact fixture :18080 /test/sqli and /test/xss. A trusted helper shares the ZAP namespace. Shared IP and Squid completion logs cannot identify individual ZAP dispatches.

The verified artifact catalog selects Network 0.29.0. Official tagged source:
https://raw.githubusercontent.com/zaproxy/zap-extensions/network-v0.29.0/addOns/network/src/main/java/org/zaproxy/addon/network/internal/ratelimit/RateLimiterImpl.java
https://raw.githubusercontent.com/zaproxy/zap-extensions/network-v0.29.0/addOns/network/src/main/java/org/zaproxy/addon/network/internal/ratelimit/RateLimiterEntry.java

The actual limiter serializes each matching entry. It calculates wait = (1000 / requestsPerSecond) - (currentTimeMillis - lastRequestTime), waits if positive, then records the admission. At 2/sec this is 500 ms minimum spacing, not a token bucket or fixed-window quota. HOST grouping shares a rule/host entry; initiator matching and most restrictive matching rule determine coverage. RateLimiter.Observer receives aggregate entry snapshots after the synchronized section. Count/first/last/average values are not a complete per-request record and cannot establish dispatch compliance.

Minimal reliable observation: an in-JVM collector inside the limiter's synchronized admission section, paired with transport-dispatch accounting for all sender initiators and redirects. It must use execution/scanner/collector identity from verified lifecycle-owned artifacts, sequence numbers, System.nanoTime plus currentTimeMillis, matched rule/group, decision/wait and a metadata-only origin/path fingerprint. No request payloads or credentials. A helper cannot forge in-JVM provenance merely by sharing an IP. Instrumentation must not replace the existing algorithm.

The pinned image has no verified collector implementing this contract. A loaded collector, complete sender coverage, non-bypassability, counter reconciliation and artifact identity must be independently observed before setting expected.collectorVerified. That property is an internal prerequisite to the offline verifier, not an API or grant field. No current production caller supplies it. Existing acceptance remains fail closed.

zapDispatchEvidence.js validates a proposed complete trace against independently verified expected identity. It enforces contiguous sequence and transport-count reconciliation, 500 ms spacing, millisecond precision, monotonic consistency, initiator/origin/path scope and wait decisions. Sub-millisecond boundary ambiguity is UNVERIFIED. Excess admissions are VIOLATION. Average completion rates are never used. Tests use explicitly synthetic observations and prove only verifier behavior.

Persist future raw sanitized collector traces and verifier output through the existing atomic private evidence bundle before cleanup, including missing/error records. Runtime wiring is intentionally not added without a verified collector: Squid records must not be relabelled as dispatch records. A gateway token or dedicated IP alone would solve attribution only; it would not provide admission decisions or actual limiter coverage.

Readiness: BLOCKED for measured enforcement. Next required work is verified collector instrumentation and its immutable artifact build/behavioral verification, followed by a bounded controlled runtime test. No scan, backend restart, grant, lease, container or image build has occurred in this task.

Confirmed supported-hook boundary (follow-up source inspection)

ZAP core 2.17.0 HttpSenderListener exists:
https://raw.githubusercontent.com/zaproxy/zaproxy/v2.17.0/zap/src/main/java/org/zaproxy/zap/network/HttpSenderListener.java
Network 0.29.0 BaseHttpSender implementation:
https://raw.githubusercontent.com/zaproxy/zap-extensions/network-v0.29.0/addOns/network/src/main/java/org/zaproxy/addon/network/internal/client/BaseHttpSender.java

notifyRequestListeners runs in sendNoRedirections only when requestConfig.isNotifyListeners(). It precedes sendAuthenticated and rate limiting. Nested listener invocation is suppressed through a thread-local guard. Listener exceptions are caught/logged and do not abort the send. Authentication retry can call sendRateLimited again without repeating the original listener call. Thus a supported HttpSenderListener/HTTP-sender script cannot establish one post-admission event per transport attempt, or enforce evidence-write failure as a dispatch failure.

The exact Network boundary is private BaseHttpSender.sendRateLimited: after rateLimiter.throttle(message, ctx.getInitiator()) and before sendImpl(...). CHECK_FOR_UPDATES_INITIATOR explicitly skips throttling and must be prohibited from reaching the fixture by the instrumented runtime. Redirects return through sendNoRedirections, but transport-internal retries and alternate client implementations require independent coverage checks; no current evidence proves those away.

Required separately approved artifact work (not performed):
1. Preserve the current immutable ZAP image and seven selected original add-on archives. Network 0.29.0 original archive SHA-256 is 082367cca24029ed0dce69ad6c4464897c63c9a2f0d5ec7ae42860e728414853.
2. Prepare/review an instrumented Network add-on built from authenticated network-v0.29.0 source. Record admission inside RateLimiterImpl's synchronized entry and correlated dispatch/abort events immediately before BaseHttpSender.sendImpl. Include auth retries, redirects and independently verified transport retry handling. Reject unmatched limiter/initiator or unavailable durable recording; do not merely log failures and send anyway. Preserve the existing throttle algorithm.
3. Record collector source/dependency hashes, offline toolchain and reproducible archive hashes. The modified .zap is a NEW artifact; it cannot retain the original archive hash or silently replace the verified selection. Existing selected dependency closure does not establish modified artifact compatibility.
4. Separately authorize offline construction of a NEW derived immutable image with the existing BuildKit-free assembler extended to validate this reviewed collector artifact. Never overwrite the pinned original image/tag. New add-on and image digests must be computed from built bytes; no digest is known yet.
5. Separately authorize isolated non-scanning hook/coverage/error-path validation; only subsequently authorize any controlled fixture traffic. Prove every relevant client uses the collector, no unobserved transport attempts occur, timestamps and sequence are complete, and collection failure stops requests. Then wire trusted output to private evidence retention and the dispatch verifier.

No supported existing hook inspected meets all admission, completeness and fail-closed requirements. No runtime modification, source patch to the Network library, image build, installation or capability promotion is authorized or performed by this assessment.
