# Module 12: Governance, Compliance & Unified Dashboard

See [the initial repository audit](module12-audit.md) for baseline gaps and architecture.
The [FE-3 completion handoff](fe3.md) documents the current versioned compliance engine,
assessment evidence model, migration 018, coverage matrix and evaluator walkthrough.
This module uses the existing React/Vite/Tailwind/Recharts frontend, Express routes,
JWT middleware and PostgreSQL pool. No ORM, scanning service, deployment or AWS
configuration was introduced. Existing project/execution/scanner routes are retained.

## Setup in this workspace

From `/home/student/hammad/CloudSentinel`:

```bash
npm install
npm run migrate:sast -w cloudsentinel-backend
npm run migrate:governance -w cloudsentinel-backend
npm run dev
```

PostgreSQL must already be running with the connection configured in `backend/.env`.
On the existing WSL setup, start it if needed with `sudo service postgresql start`.
SAST persistence requires migration 016 (`npm run migrate:sast -w cloudsentinel-backend`),
which adds classification columns while keeping historical rows UNKNOWN.
Use the project's existing schema and prior scanner migrations; do not reapply
`schema.sql` to an existing populated database. Migration 017 only adds governance
objects and is repeatable. Migration 018 adds configuration evidence and target/control
assessment history. Both were applied successfully locally. To apply only the new
FE-3 change on an existing Module 12 database, run
`npm run migrate:compliance -w cloudsentinel-backend`. Migration 017 is unchanged.

To launch separately, use two terminals at the repository root:

```bash
npm run dev:backend
npm run dev:frontend
```

Backend defaults to port 3000; Vite to 5173 (may select 5174 if busy). Preserve the
existing `VITE_API_BASE_URL=http://localhost:3000/api` frontend setting. If port 3000
already has a healthy CloudSentinel backend, stop it in its original terminal with
Ctrl+C before restarting it to load the new route. Do not launch a duplicate backend.
Governance needs PostgreSQL and existing stored scan records; SonarQube, Trivy,
ZAP, Kubernetes and AWS are not needed to view/export those records.

## Data flow and database changes

`POST /api/governance/sync` reads completed, owner-scoped source records. Opening a
governance page or selecting Refresh stored results invokes it. This is a stored-data
import, never a scan. Filters use GET queries against persisted normalized records.
Imports use a transaction and per-user advisory lock. Database uniqueness protects
concurrent imports. Governance does not alter scanner source rows.

Migration `backend/migrations/017_governance.sql` creates:

- `governance_findings`: project/source/resource identity, current severity, explicit
  classification, current reviewed lifecycle, references and structured mappings.
- `governance_scans`: source scan identity, timestamp, outcome and detail completeness.
- `governance_observations`: durable per-finding/per-scan provenance and sanitized
  evidence. These survive later source detail replacement.
- `governance_status_history`: owner-reviewed status transitions with reasons.
- `iac_scans.configuration_evidence` (018): sanitized explicit Trivy check outcomes.
- `governance_configuration_targets` / `governance_control_assessments` (018):
  source-linked resource assessments and immutable per-scan history.

Deduplication uses SHA-256 of project ID, source, vulnerability/rule identity and
resource location. Finding row IDs, scan IDs, severity and timestamps do not change
identity. A package version or affected image is part of its resource, so a different
version/image is not silently merged. Cross-scanner deduplication is deliberately
not attempted: distinct evidence from different scanners remains distinguishable.
First/last detection timestamps and the newest observed severity are maintained.
Imports do not resolve absent findings. Reviewed status persists until another owner
review; a subsequent observation is visible in the detail view. This is a manual
lifecycle, not automatic proof that remediation succeeded.

| Source | Stored evidence | Import eligibility / limitations |
| --- | --- | --- |
| SAST | scan_results → scan_history | Completed; linked details counted against total_issues. Bugs/code smells excluded. Unclassified rows and pending hotspots explicitly require review; reviewed SAFE/FIXED hotspots excluded. |
| Dependency | sbom_components → dependency_scans | Completed; only rows with CVE become findings; raw inventory still verifies detail counts. |
| IaC | iac_findings → iac_scans | Completed; exact misconfiguration ID, file and remediation. |
| Image | image_vulnerabilities → image_scans | Completed or BLOCKED; BLOCKED is a real result rejected by a security gate. |
| DAST | dast_findings → dast_scans | Completed; endpoint query/credentials removed, CWE retained. |
| Active DAST | active_dast_executions.result.findings | Optional schema; completed-with/no-findings only. Reads existing output, never enables active scanning. |
| Kubernetes | Not imported | kubernetes_scans lacks project/owner linkage and can contain fallback issues. Unsafe to aggregate. |

Historical dependency/IaC detail deleted by existing scanner routes cannot be
reconstructed. Import count mismatches remain incomplete assessments and do not
contribute to score coverage. Normalized findings imported before future replacement
are retained. Previously deleted records do not turn into synthetic trend data.

## API, permissions and filters

All endpoints require the existing JWT bearer token. Every source/read/detail/update
query checks `projects.user_id`. Unknown and unauthorized projects/findings return
404, malformed input returns 400, missing governance schema returns 503. Report
responses use no-store caching. Owner-only status updates require a 3–1000-character
reason and are recorded transactionally.

| Method | Path under `/api/governance` | Result |
| --- | --- | --- |
| POST | /sync | Import observations and return source availability / limitations |
| GET | /summary | Shared counts, score, charts, coverage, latest scans, priority issues and mappings |
| GET | /findings | Paginated normalized findings |
| GET | /findings/:id | Finding, scan observations and status audit history |
| PATCH | /findings/:id/status | Reviewed OPEN / RESOLVED / ACCEPTED_RISK / FALSE_POSITIVE |
| GET | /export/security | Security PDF |
| GET | /export/compliance | Compliance PDF |
| GET | /export/csv | Matching findings CSV with explicit versioned mappings, across all pages |
| GET | /compliance | Versioned mappings and evidence-based assessment metrics |
| GET | /compliance/controls/:controlId | Owner-scoped current resource results and paginated evidence history |
| GET | /export/compliance-csv | Project/control assessments, provenance and shared metrics |

Shared filters: `project`, `source`, `severity`, `status`, `search`, `from`, `to`,
`owaspVersion` (2021/default or 2025), `benchmark` (docker-cis-1.6.0),
`assessment` (PASS/FAIL/NOT_ASSESSED/NOT_APPLICABLE/ERROR),
`mapping`, `sort` (`severity`, `newest`, `oldest`). Dates are ISO YYYY-MM-DD,
inclusive UTC days. Pagination: `page`, `pageSize` (1–100, default 25).
Search matches title, scanner identity and stored CVE/CWE references; wildcard
characters are escaped. SQL values are parameterized and sort expressions allowlisted.
Filters persist in the URL and are carried between module views and exports.

Read transactions use repeatable-read snapshots so one response/report has consistent
metrics. Exports include all matching rows, not just the visible page. An export is a
fresh snapshot: records changed after a dashboard response may change the report.
Current finding status/severity is used even for a historical observation date range;
trends describe actual observations, not historical open-status balances.

## Framework mapping and assessment policy

OWASP 2021 remains the compatibility default; 2025 is separately selectable. The
registry contains all ten categories and official mapped-CWE lists for each version,
pinned to OWASP's published repository revision. There are 197 CWE associations for
2021 and 249 for 2025. These are category associations, not a claim that every CWE
can be detected by current scanners. Unknown scanner identities remain unmapped.

The mapping engine uses explicit CWE references, known component CVEs and four exact
Trivy configuration rule identities. Every persisted association includes version,
category, finding ID, justification, rule, source URL and registry revision. Repeated
references do not duplicate category associations. Both versions can coexist without
renumbering old identifiers. OWASP 2025 reclassifies SSRF under A01, moves Injection
to A05 and adds exceptional-condition handling; mappings come from each version's
own published lists rather than a naive cross-version number translation.

CIS Docker Benchmark 1.6.0 registers 12 image/build-file controls. Four have supported
static checks: 4.1/DS0002, 4.6/DS0026, 4.7/DS0017 and 4.9/DS0005. The other eight
remain unsupported/manual and Not Assessed. This is not a full Docker, Kubernetes,
Linux or host/runtime benchmark implementation. The [FE-3 coverage matrix](fe3.md)
contains source references, licensing, supported aliases and exact limitations.

Configuration assessments are separate from finding mappings. The existing IaC
command now requests `--include-non-failures` and retains only sanitized explicit
check outcomes on its project-owned scan. No scanner was executed for this change.
PASS requires an explicit timestamped check on every known Dockerfile target in the
latest completed stored assessment. One failed target establishes FAIL; missing
checks remain Not Assessed; unrecognized/EXCEPTION results are ERROR. NOT_APPLICABLE
requires explicit verified scope evidence; the current Trivy adapter never invents
it. Legacy stored exact-rule IaC failures can establish FAIL, never PASS.

Assessment history survives source-detail replacement. Source scan/target/control
keys prevent duplicate assessments. Project ownership follows the source scan FK;
unassigned Kubernetes audit rows are never guessed into a project. A finding's
manual lifecycle does not overwrite configuration assessment evidence.

Pass rate = PASS / (PASS + FAIL), or Not assessed when none were evaluated.
Coverage = (PASS + FAIL) / (registered project-control slots minus verified N/A).
ERROR and missing evidence remain in the coverage denominator. These shared internal
metrics drive overview, charts, APIs, PDF and compliance CSV; they do not assert
CIS certification. Project/source/date scope selects assessments; finding search,
severity/status/category filters only affect mapped finding counts. Selecting an
assessment status filters rows without recalculating a misleading pass-only rate.

## Score and analytics

Severity normalization: BLOCKER → CRITICAL, MAJOR → HIGH, MINOR → LOW,
INFORMATIONAL → INFO; otherwise retain recognized severity, unknown stays UNKNOWN.
No CVSS value is invented. Unknown severities conservatively receive Critical weight.

Let W be severity-weighted unique unresolved findings: Critical 10, High 5,
Medium 2, Low 1, Info 0, Unknown 10. OPEN and ACCEPTED_RISK count; RESOLVED and
FALSE_POSITIVE do not. Pending review findings count conservatively and remain
explicitly labeled rather than being reclassified as confirmed vulnerabilities.

Let P be selected authorized project count, and C be complete latest project/scanner
slots divided by `5 × P` (SAST, dependency, IaC, image, DAST). Active DAST is optional
and does not inflate the denominator or coverage. If there are no complete slots,
return `null` / Not assessed. Otherwise:

```
score = round(95 × C / (1 + W / (10 × P)))
```

This academic posture indicator is deterministic and capped at 95, including empty
findings. It does not assert perfect security, account for asset criticality, prove
scanner scope completeness or establish compliance. It measures stored detail
coverage only. Missing core sources lower the indicator rather than silently being
considered secure. Project/source/date filters define assessment scope; severity,
status, search and mapping filters define its finding population. The UI and reports
explicitly call it a filtered posture indicator. No historical scores are fabricated.

Seven Recharts visualizations plus the score card show severity, project, scanner,
current lifecycle, actual UTC observation days, OWASP mapping and CIS statuses.
No missing days are interpolated into fake historical observations. There is no
historical status reconstruction. All cards/charts and reports reuse the backend
snapshot/scoring functions. Loading, empty/error/retry states are implemented.

## Reports and document safety

PDFKit is the only new runtime dependency; the repository previously had no PDF
library. Separate security/compliance PDFs include scope, timestamp, scan date range,
active filters, executive summary, coverage, severity/lifecycle totals, findings,
resources, scanner IDs, mappings, remediation, scoring and limitations. Security
reports include priority issues; compliance reports include category/control counts
and gaps. Reports wrap text, paginate and print page numbers. Built-in Helvetica
keeps deployment simple; unsupported non-Latin glyphs are replaced with spaces,
so internationalized report typography remains a limitation.

Scanner text is treated as text, stripped of markup/control characters and common
credential assignments; endpoint query strings and URL credentials are removed.
Evidence uses an allowlist (table, record/scan/rule/type/severity/review), never raw
scanner requests, response bodies, environment, repository credentials or tokens.
CSV quotes fields and mitigates spreadsheet formula injection. React escapes
rendered text. PDF output does not evaluate HTML or scanner scripts.

## Verification and demonstration

```bash
npm run test:governance -w cloudsentinel-backend
npm run test:governance:db -w cloudsentinel-backend
npm run verify:governance -w cloudsentinel-backend
npx playwright install chromium
npm run test:governance -w cloudsentinel-frontend
npm run build
```

The database test creates a unique temporary schema, copies source table shapes,
adds clearly labeled test-only data, serves actual authenticated Express routes and
removes its schema on completion. It tests all six adapters, repeated scan
observations, multi-project ownership, count/page/filter consistency, date trends,
status history and PDF/CSV endpoints. It does not run a scanner or write fixtures to
public application tables. `GOVERNANCE_DB_TEST=1` is required to opt in.
Browser tests intercept API requests with explicitly labeled, browser-only fixtures;
they complement real PostgreSQL/HTTP integration tests, not replace them. Playwright
is a development dependency only. The verify script imports actual stored records
for the first project owner and checks repeated import and report generation.

Evaluator demonstration:

1. Sign in and open Dashboard. Refresh stored results; show latest scans, incomplete
   coverage and unavailable integrations. Explain reviewed vs confirmed findings.
2. Open Findings, select project/source/severity, search a CVE/rule, sort and paginate.
   Open details and trace the source scan/record, review class and remediation.
3. Change a finding status with a review reason; verify history and shared metrics.
   Use a test project or restore the original status with another documented review.
4. Open Compliance, select an OWASP category or CIS control to drill into supporting
   findings. Explain version, rule/CWE basis, unassessed coverage and lack of certification.
5. Open Analytics and change project/date filters. Explain observation history and
   score formula. An unassessed project must not show a perfect security score.
6. Open Reports with those filters and download security PDF, compliance PDF and CSV.
   Compare counts with the same scope. Exports include all matching pages.
7. For currently absent dependency/IaC evidence, run the isolated integration test
   as a technical demonstration; do not present test fixtures as real findings.

## Known limits

- No new scanning, external attacks, deployment or AWS setup was performed.
- Kubernetes and absent active-DAST schema remain unavailable in governance.
- CIS is a registered image/build-file subset: four explicit static checks support
  PASS/FAIL; eight require external/manual evidence. No production N/A adapter exists.
  Current local records contain no retained Docker configuration evidence, so all
  48 authorized project-control slots are Not Assessed; no passes were fabricated.
- Historical deleted source details cannot be recovered. Refresh must occur before
  a future upstream scan replaces details to retain their observations.
- No scheduling/queue was added; import occurs on page entry or explicit refresh.
- Pagination runs in SQL; analytics/PDF materialize owner-scoped matching findings
  in memory. This is appropriate for current academic datasets, not yet a streamed
  large-enterprise analytics/export architecture.
- No automatic fixed/reopened inference, historical lifecycle snapshots, opaque
  risk scoring or invented compliance percentages.
- Browser tests use fixtures; the separate backend integration and stored-data
  verification exercise real PostgreSQL and report generation.

## Delivery matrix and executed evidence

| Requirement | Status | Implementation | Verification |
| --- | --- | --- | --- |
| FE-1 Aggregation | Complete for compatible stored sources; upstream limits documented | migration 017; services/governance/{normalize,store,query}.js; routes/governance.js | Real import: 93 observations → 69 unique findings; repeated import: 0 new observations. Isolated six-adapter test passes, including concurrent import and source-detail deletion retention. |
| FE-2 Findings/dashboard | Complete | GovernanceDashboard.jsx, Dashboard.jsx, App.jsx; query.js; governance routes | Unit normalization tests; authenticated PostgreSQL/HTTP isolation, pagination, filtering and lifecycle; browser search/sort/paging/details/status test. |
| FE-3 OWASP/CIS | Complete for supported static-assessment scope; full benchmark coverage unavailable | registry.js, configuration.js, assessments.js, migration 018, ComplianceOverview.jsx, report.js | 16 FE-3 unit tests; explicit outcome persistence and historical API/PDF/CSV integration; 8 browser tests. See fe3.md. |
| FE-4 Reporting | Complete for supported stored data | report.js; authenticated export routes; Reports navigation | Real security PDF 30,907 bytes, compliance PDF 32,964 bytes in initial verification; PDF/CSV integration tests and four browser downloads pass. Empty and long multipage PDF tests pass. |
| FE-5 Analytics/score | Complete for available observations | analytics.js; seven Recharts views and score card | Score/coverage/empty-state unit tests, real-date PostgreSQL tests, browser chart/filter/loading/error tests and mobile viewport check pass. |

Executed commands:

- `node backend/test/governance.test.js`: **12/12 tests passed**, including normalization,
  classification, dedup identity, mappings, score, validation, owner-query scope,
  text sanitization, CSV formula escaping and empty/multipage PDFs.
- `GOVERNANCE_DB_TEST=1 node --test backend/test/governance.integration.test.js`:
  **1 integration workflow passed**, containing the PostgreSQL/HTTP assertions above.
  An initial test connection-copy failure was fixed (pg hides password properties).
  A date-boundary assertion exposed session-timezone-dependent filtering; filters
  now explicitly use UTC and the rerun passes.
- `node backend/scripts/verify-governance.js`: real stored-data import and both report
  types succeeded; 69 unique findings; repeat import zero; initial score 7/100,
  complete slots 10/20, 29,196-byte findings CSV. These are observed local records,
  not universal expected counts. They include explicitly classified review findings.
- `node --test backend/test/sast-classification.test.js backend/test/sast-evidence.test.js backend/test/sast-gate.test.js backend/test/unified-report.test.js frontend/src/utils/*.test.js`:
  **all six test files passed**.
- `npm run test:governance -w cloudsentinel-frontend`: **8/8 Chromium tests passed**.
  Browser API responses are isolated test fixtures, as described above.
- `npm run build`: **passed**. Vite reports an ~817 kB JavaScript chunk warning;
  splitting the existing application bundle is not part of this module.
- `npm run test:compliance -w cloudsentinel-backend`: **16/16 tests passed**.
- Additional FE-3 integration verifies PASS/FAIL/ERROR and a labeled future-adapter N/A fixture, duplicate prevention, versioned APIs, historical evidence and PDF text/CSV metric consistency.
- Expanded targeted regression suite: **64/64 tests passed** across ten files.
- `git diff --check`: **passed**.

No claim is made that active scanners were executed or that every existing unrelated
backend test was run. No AWS, deployment, production infrastructure, Git commit or
push was performed. The running backend must be restarted to load the new routes.

## Changed-file inventory

Paths below are relative to the repository root.

| Files | Purpose |
| --- | --- |
| backend/migrations/017_governance.sql | Add four durable tables and scoped indexes, without altering source findings. |
| backend/services/governance/normalize.js | Normalization, source classification, redaction and dedup identity. |
| backend/services/governance/registry.js | Versioned evidence-based OWASP/CIS registry. |
| backend/services/governance/store.js | Transactional owner-scoped stored-result import and scan observations. |
| backend/services/governance/query.js | Validated filters, SQL pagination and owner scope. |
| backend/services/governance/analytics.js | Consistent summaries, actual observation trends, coverage and score. |
| backend/services/governance/report.js | PDFKit security/compliance reports and safe CSV. |
| backend/routes/governance.js; backend/server.js | Authenticated route capabilities and Express registration. |
| backend/scripts/migrate-governance.js | Transactional migration 017 runner. |
| backend/scripts/inspect-governance.js | Credential-free source table availability/count inspection. |
| backend/scripts/verify-governance.js | Real stored-data import/dedup/report verification. |
| backend/test/governance.test.js | Pure business-rule and document tests. |
| backend/test/governance.integration.test.js | Isolated PostgreSQL and real authenticated HTTP workflow. |
| frontend/src/pages/GovernanceDashboard.jsx | Shared operational module views, filters, charts, details, review and exports. |
| frontend/src/pages/{Dashboard,ComplianceDashboard}.jsx | Preserve existing route entry points through shared view. |
| frontend/src/App.jsx | Add protected findings, analytics and reports routes. |
| frontend/src/components/Navbar.jsx | Navigation additions; replace fabricated notifications with honest unavailable feed state. |
| frontend/src/styles.css | Responsive governance layout, retaining existing theme. |
| frontend/playwright.config.js; frontend/test/governance.spec.js | Browser verification with isolated fixtures. |
| backend/package.json; frontend/package.json; package-lock.json | PDFKit runtime dependency, Playwright development dependency, repeatable commands. |
| .gitignore | Exclude generated browser test artifacts. |
| docs/module12-audit.md; docs/module12.md; README.md | Baseline audit, setup, API/mapping/scoring policy, test evidence, evaluator guide and module documentation link. |

Current FE-3 changed-file inventory, real-data observations and detailed test results
are in [the FE-3 handoff](fe3.md); earlier PDF sizes above record the initial Module 12 run.

## Compliance aggregation correction (18 October 2026)

See [the implementation report](compliance-pipeline-fix.md) for the current all-source
assessment calculation, explicit CIS Controls associations versus Docker Benchmark
states, unchanged main-dashboard/security score contract, executed tests and local
verification. It supersedes earlier UI/calculation descriptions in this document;
no new scanner, migration or dashboard layout was introduced.

## Matching percentages versus assessment rates

The [matching correction report](compliance-matching-fix.md) supersedes the earlier
combined OWASP/Docker overall-slot formula. The existing bars now show distinct
OWASP X/10 and CIS Controls X/18 matching. Docker assessment pass rate and coverage
remain separate, using explicit requirement evidence; no overlapping framework units
are added together. See that report for actual records, files, tests and limitations.
