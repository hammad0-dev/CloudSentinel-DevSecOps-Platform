Production Dependency/SBOM with Snap Trivy

The Dependency route now uses a private execution-owned checkout under ~/snap/trivy/common/dependency-checkouts when TRIVY_CMD points into /snap/. It uses the verified cache at ~/snap/trivy/common/cs-db-verified-3cj1v216/cache by default. Explicit TRIVY_CACHE_DIR and DEP_CLONE_DIR overrides must remain under ~/snap/trivy/common for Snap. Non-Snap defaults are preserved.

Snap subprocesses force TRIVY_SKIP_DB_UPDATE=true, TRIVY_SKIP_JAVA_DB_UPDATE=true, TRIVY_SKIP_CHECK_UPDATE=true and TRIVY_OFFLINE_SCAN=true. Both vulnerability/license JSON and CycloneDX generation are mandatory; malformed output or SBOM command failure fails the stage. No production cache is overwritten.

Coverage is returned with the successful Dependency response. MANIFESTS_WITHOUT_INVENTORY fails closed. NO_SUPPORTED_MANIFESTS_OBSERVED reports the limited observation, and does not imply that unsupported manifests or binaries are vulnerability-free. Java archives require a separately verified Java DB; updates remain disabled.

The prior Project 11 validation reported zero language files. Its checkout was removed before manifest inventory was captured. Its exact source inventory therefore remains unconfirmed; no further checkout/download was performed for this source-only task. The next authorized execution must inspect the returned coverage and package inventory.

A running backend must load these source changes before relying on the new paths. No restart is performed by this change. Ordinary Active DAST stays disabled.
