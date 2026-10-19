# Module 12 repository audit (before implementation)

Baseline: clean working tree. Inspected source tree, root/workspace packages, schema,
all migrations, Express boot/auth/project/report routes, scanner persistence paths,
React routes/navigation/dashboard/compliance, shared components and test conventions.

Architecture: React 18 / Vite 6 / Tailwind CSS / CSS variables / Recharts;
Express 4 CommonJS, JWT bearer auth (`req.user.id`), PostgreSQL via `pg`, no ORM.
Projects belong to `projects.user_id`; no additional role model exists.
Existing tests use Node's test runner. No browser test dependency exists.

| Requirement | Baseline gap |
| --- | --- |
| FE-1 | Execution reports combine five scanners but no durable cross-scan normalized inventory or observations. |
| FE-2 | Dashboard uses SAST summaries plus hardcoded trends, compliance percentages, deltas and fixed counts. No central finding lifecycle or details. |
| FE-3 | SAST regex mapping only; CIS Controls confused with Benchmarks; absent findings treated as passes. |
| FE-4 | Execution JSON and frontend HTML/JSON export; no PDF/filtered CSV or unified report scope. |
| FE-5 | Recharts reusable; no shared score, trustworthy historical series, scope/coverage accounting. |

Sources: `scan_results` -> `scan_history` (migration 010); SAST type/review
classification (016) must exclude bugs/code smells, label unknown/hotspots for review.
`sbom_components` -> `dependency_scans` (only rows with CVE are vulnerabilities).
`iac_findings` -> `iac_scans`; `image_vulnerabilities` -> `image_scans`
(BLOCKED image scans contain real completed assessment data).
`dast_findings` -> `dast_scans`; optional `active_dast_executions.result.findings`.
Dependency/IaC scans replace earlier detail rows: unrecoverable history must be
reported, never fabricated. New governance observations will retain imported evidence.
`kubernetes_scans` has neither project nor owner identity and its route fabricates
fallback issues; exclude from governance pending trustworthy owner-scoped integration.
No scanning, deployments, AWS changes, commit or push are part of this work.

Reuse: existing JWT, pg pool, project ownership, Axios interceptor, PageHeader,
SeverityBadge, Tailwind card/input/button/table classes, Recharts, protected routes.
Additive migration and dedicated governance services/routes avoid altering scanner execution.
