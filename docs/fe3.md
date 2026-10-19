# FE-3 completion handoff — 18 October 2026

**Status: Complete for supported assessment scope.** This means versioned OWASP
mapping and explicit static Dockerfile check assessments are implemented, persisted,
authorized, displayed, exported and tested. It does not mean full CIS compliance,
complete scanner coverage, Kubernetes ownership recovery or official certification.

The [FE-3 audit](fe3-audit.md) records the before-change gaps. Existing Module 12
normalization, deduplication, authentication, finding lifecycle, Recharts and PDFKit
were reused. The security posture scoring function and migration 017 were preserved.
No runtime dependency was added. No active DAST, scanning run, deployment, AWS
configuration, commit or push was performed.

## Supported framework and benchmark coverage

| Framework/version | Target types | Rules and count | Evidence | Unsupported / unassessed scope | Verification |
| --- | --- | --- | --- | --- | --- |
| OWASP Top 10:2021 | Stored SAST/DAST/component/IaC findings with verified identifiers | 10 categories; 197 published CWE associations; component-CVE A06; four exact Dockerfile rules → A05 | Explicit stored CWE, component CVE or recognized Trivy rule | A registry is not scanner coverage. Sonar rules without retained CWE metadata and unknown identities remain unmapped. | Unit version/multi-map/dedup/unmapped tests, real records, database persistence/filter tests, browser category/version drill-down |
| OWASP Top 10:2025 | Same supported evidence types | 10 categories; 249 published CWE associations; component-CVE A03; four exact Dockerfile rules → A02 | Each version's own official category lists | No automatic ID renumbering or assumed detection of every category | SSRF A10:2021 → A01:2025, Injection A03:2021 → A05:2025 tested; real versioned records and PDF |
| CIS Docker Benchmark 1.6.0 — image/build-file subset | Project-owned Dockerfiles assessed by existing Trivy config integration | 12 registered controls; 4 supported static checks: 4.1 DS0002, 4.6 DS0026, 4.7 DS0017, 4.9 DS0005 | Explicit per-target PASS/FAIL/error outcomes retained on completed IaC scans; exact legacy failure evidence | Eight registered controls (4.2–4.5, 4.8, 4.10–4.12) require unavailable manual/external evidence. Other Docker sections and runtime/built-image validation unavailable. | Exact alias/rule, persistence, repeated import, coverage, multi-target, history, owner isolation, PDF/CSV/browser tests |
| Kubernetes / Linux benchmarks | No supported assessment integration | None registered as operational | Existing Kubernetes audit lacks owner/project identity; image vulnerability output does not prove host hardening | Unassigned audits are excluded. Deployment success, namespace names and resource labels are not ownership/benchmark evidence. No project or benchmark version is guessed. | Exclusion maintained; no new cluster/host calls |

CIS input aliases are normalized exactly: `DS002`, `DS0002`, `DS-0002` and
`AVD-DS-0002` refer to DS0002 (similarly for the other three checks). Arbitrary IDs,
keyword descriptions or invented CIS control labels never establish an assessment.

## Version references and licensing

OWASP's [official project page](https://owasp.org/projects/top-ten?lang=en) identifies
2025 as the current release. CloudSentinel retains 2021 as the backward-compatible
default and offers 2025 explicitly. 2025 changes category order/names, expands supply
chain coverage, folds SSRF into access control and adds exceptional-condition risks.
It is not safe to translate category numbers mechanically.

The offline registry was generated from the official `OWASP/Top10` category documents
at revision `3a31f35346c3f4e90f350395124382fa53af2afe`. Each category records its exact
source and published CWE list. See [OWASP source](https://github.com/OWASP/Top10/tree/3a31f35346c3f4e90f350395124382fa53af2afe),
[2021 categories](https://top10.owasp.org/2021/) and
[2025 categories](https://top10.owasp.org/2025/).
The adapted metadata is attributed to OWASP Foundation and contributors under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); the source license
is included next to `owasp-cwes.json`. Full category descriptions are not copied.
`python3 backend/scripts/update-owasp-registry.py` reproducibly rebuilds the pinned
metadata; it is a maintenance tool, never a runtime/network requirement.

The Docker mapping follows Aqua's Apache-2.0
[pinned Trivy compliance profile](https://github.com/aquasecurity/trivy-checks/blob/80a592945fe732fd8f60819efc0ca98a49ee9d79/pkg/compliance/docker-cis-1.6.0.yaml)
and links to [CIS Docker](https://www.cisecurity.org/benchmark/docker). The registry
contains short original summaries, check identifiers and provenance, not a copied
proprietary benchmark document. The version is explicitly the 1.6.0 profile; it is
not a claim to implement the latest or complete CIS benchmark.
The [Trivy config reference](https://trivy.dev/docs/latest/references/configuration/cli/trivy_config/)
documents `--include-non-failures`; the installed local `trivy config --help` also
confirmed the option without running a scan.

## Evidence flow and ownership

1. The existing project-owned IaC scan command retains its format, exit code and
   scan endpoint, adding `--include-non-failures`.
2. `captureConfiguration()` validates the report envelope and extracts only explicit
   Dockerfile check outcomes. It excludes raw configuration, code snippets, secret
   values and scanner response bodies. Non-failure rows do not enter finding totals.
   Invalid reports fail the source scan rather than becoming a successful empty result.
3. Completed source scans remain linked through `governance_scans.project_id`.
   Target resources and observations are imported transactionally during existing
   governance refresh. Legacy exact-rule failures can establish FAIL only.
4. Each assessment retains target, benchmark/version/control, check, outcome,
   timestamped source scan evidence, optional finding ID and registry revision.
   Unique target/control/check keys prevent reimport duplicates. Duplicate conflicting
   outcomes in one source result are recorded as ERROR.
5. Current project results use the latest completed stored IaC assessment in the
   selected project/source/date scope. Previous assessments remain accessible through
   paginated control history. Later missing checks are Not Assessed; older failures
   are not silently reused as current passes. A failed later scan is not a new complete
   assessment; the displayed source timestamp identifies the last retained result.
6. Every query joins through project ownership. There is no public endpoint accepting
   arbitrary evidence or allowing a user to submit a PASS. Cross-owner project requests
   return 404; an owner's unfiltered control history contains only their observations.

Unassigned `kubernetes_scans` data is left untouched and excluded. Project identity
cannot be reconstructed safely from namespace labels, guessed names or historical
fallback issues. The new code never queries a cluster or infers a new relationship.

Stored normalized findings are remapped during sync, including findings whose original
source rows were already deleted. Finding IDs, dedup identities, observations, lifecycle
and first/last seen dates are unchanged. Every association includes finding ID, framework
ID/version, category/control ID, justification, mapping rule/source and registry revision.
Mapping updates neither create vulnerabilities nor manufacture CIS assessment results.

## Assessment states and metrics

- **PASS:** Explicit timestamped supported check passes on every known Dockerfile
  target in the latest project assessment. It is a static indicator, not runtime proof.
- **FAIL:** At least one supported target has an explicit failing check. A known
  failure is sufficient even when other resources remain unassessed.
- **NOT_ASSESSED:** Missing check/target/scan, insufficient provenance, or unsupported
  manual control. An empty vulnerability list never becomes a pass.
- **ERROR:** Unrecognized or EXCEPTION outcomes, or contradictory duplicate outcomes.
  EXCEPTION is not treated as Not Applicable.
- **NOT_APPLICABLE:** Requires explicit verified applicability, reason and source
  reference. The data model/calculator support it, but the current Trivy adapter
  does not emit it. Tests use a labeled future-adapter fixture; production N/A is
  never inferred from absent findings, absent targets or an ignored check.

Metrics count **project-control slots**, not vulnerabilities or individual container
occurrences. A project has 12 registered slots. A missing result on another known
target prevents the whole project/control from passing. Unknown technology/ownership
is not silently excluded as verified N/A.

```
assessed = PASS + FAIL
applicable = registered project-control slots - verified NOT_APPLICABLE
passRate = PASS / assessed * 100        # null / Not assessed when assessed == 0
coverage = assessed / applicable * 100 # null if no applicable slots; otherwise 0 is valid
```

ERROR and missing checks stay in the coverage denominator. Coverage describes only
the registered image/build-file subset, not the complete benchmark. Finding status,
severity, search and OWASP category filter mapped findings independently; they cannot
remove failed assessments and inflate pass rate. Assessment-state filters select rows
without changing the full-scope metric denominator. Project/source/date filters select
assessment scope. Historical date selection uses the source observation timestamps;
manual finding lifecycle remains current, as before.

The same backend model drives overview, controls, project gaps, charts, APIs, PDF and
CSV. Security posture scoring remains a separate unchanged algorithm. No CIS metric
is used as a CVSS score or certification percentage.

## API and interface

Existing Module 12 endpoints remain. New/extended capabilities:

| API under `/api/governance` | Behavior |
| --- | --- |
| POST /sync | Imports stored findings, refreshes versioned mappings, imports explicit control evidence; reports `updatedMappings` and `importedAssessments` alongside existing fields |
| GET /summary | Existing dashboard response with expanded `compliance` model and unchanged posture score |
| GET /compliance | Same compliance model used in summary/reports |
| GET /compliance/controls/:controlId | Registered control, current project/target results and paginated assessment history |
| GET /findings | Existing pagination; `mapping=UNMAPPED` selects OWASP-unmapped findings for selected version |
| GET /export/compliance | Existing branded PDF, now including versions, assessment date/metrics, project controls and source evidence |
| GET /export/compliance-csv | Project/control rows, resource, check, source scan, outcome, evidence, remediation, pass rate and coverage |
| GET /export/csv | Existing findings CSV, now also includes explicit versioned mapping IDs and explanations |

New validated filters: `owaspVersion=2021|2025`,
`benchmark=docker-cis-1.6.0`, `assessment=PASS|FAIL|NOT_ASSESSED|NOT_APPLICABLE|ERROR`.
Existing project/source/date/search/severity/status/sort/page/pageSize filters remain.
History pagination uses `page` and `pageSize` (maximum 100).

The old `/api/sast/compliance/:projectId` endpoint now uses the shared governance model,
preserving familiar summary keys while returning null instead of a fabricated score
when unassessed. The compliance section of `/api/sast/report/:projectId` also uses the
shared model. The old keyword/CIS-Controls mapper and absent-category-as-pass formula
were removed; no competing assessment service was introduced.

Compliance UI keeps the existing theme/navigation and adds version/category/benchmark/
state selectors; severity/project/category counts; unmapped drill-down; project/control
statuses, support and timestamps; evidence/history with retry and pagination; failed
project gaps; and four shared Recharts views. There is one supported benchmark family,
so no comparison against unavailable benchmarks is fabricated. Report downloads remain
on the existing Reports view and now include compliance CSV.

## Database setup and local run

Migration **018_compliance_assessments.sql** is additive and repeatable:

- Adds nullable `iac_scans.configuration_evidence`; old rows remain untouched/null.
- Adds `governance_configuration_targets` linked to governance source scans.
- Adds `governance_control_assessments` linked to targets and optional findings, with
  explicit version, state, evidence and uniqueness/indexes.

It was applied locally using the existing `.env` connection. Migration 017 was not
modified. No test fixture was inserted into public application tables.

From `/home/student/hammad/CloudSentinel`:

```bash
# Existing Module 12 installation:
npm run migrate:compliance -w cloudsentinel-backend

# For a fresh governance installation, this applies both additive 017 and 018:
npm run migrate:governance -w cloudsentinel-backend

# Restart the existing backend before loading new API code; do not duplicate port 3000.
npm run dev
```

Use the configured PostgreSQL service; if stopped in WSL, `sudo service postgresql start`.
No SonarQube/Trivy/ZAP/cluster service is needed to view stored records or reports.
Do not run new scans just to populate the dashboard. The source capture hook takes
effect only when a separately authorized future IaC scan is run.

## Executed verification

| Command | Result |
| --- | --- |
| `npm run test:compliance -w cloudsentinel-backend` | 16/16 FE-3 unit tests pass |
| `node backend/test/governance.test.js` | 12/12 normalization/scoring/export regression tests pass |
| `npm run test:governance:db -w cloudsentinel-backend` | Isolated PostgreSQL + authenticated HTTP workflow passes; repeated 017/018 migrations, mappings, explicit PASS/FAIL/ERROR, N/A fixture, duplicate checks/imports, ownership, date/version filters, history pagination, legacy endpoint and PDF/CSV consistency |
| `npm run test:governance -w cloudsentinel-frontend` | 8/8 Chromium browser tests pass, including version/unmapped filtering, explicit control evidence, retry, metrics, four downloads and mobile layout |
| Targeted regression command below | 64/64 tests pass across ten existing files |
| `npm run build` | Vite production build passes; existing large application chunk warning remains |
| `node backend/scripts/verify-governance.js` | Actual local records and report generation succeed; repeated imports create no duplicates |
| `git diff --check` | Pass |

Regression command:

```bash
node --test backend/test/sast-classification.test.js backend/test/sast-evidence.test.js backend/test/sast-gate.test.js backend/test/sast-gate-counting.test.js backend/test/sast-linkage-contract.test.js backend/test/unified-report.test.js backend/test/dependency-runtime.test.js backend/test/kubernetes-security.test.js frontend/src/utils/executionReport.test.js frontend/src/utils/executionScan.test.js
```

The browser suite initially found that the new CSV export endpoint lacked its visible
button. The button was added and all eight tests passed on rerun. No unresolved test
failure remains in the executed suites. The unrelated full backend/active-scanner suite
was not run; no claim is made about its outcome.

The database fixture is isolated in a temporary schema and removed afterward. It runs
the real capture/import/mapping/assessment/persistence/HTTP/report code. PDF streams are
parsed in the test to verify **50% pass rate and 16.67% coverage**, matching the API and
CSV for the explicit PASS/FAIL/ERROR fixture. A separate labeled future-adapter N/A
fixture verifies a denominator change to 11 applicable slots and 18.18% coverage.
Browser responses are labeled fixtures and are not production evidence.

Actual application database observations after this change:

- 69 normalized findings retained; repeated import adds zero finding observations
  and zero assessments. Original 93 historical observations are preserved.
- OWASP 2021: 15 mapped / 54 unmapped unique findings.
- OWASP 2025: 29 mapped / 40 unmapped unique findings.
- Four authorized projects × 12 registered controls = **48 Not Assessed** slots,
  **zero** fabricated PASS/FAIL/N/A results, null pass rate, 0% registered coverage.
- Security posture remains **7/100**, with complete detail slots **10/20**.
- Security PDF and compliance PDF generation succeed; observed final sizes about
  33.6 kB and 37.5 kB. Findings CSV includes mappings. Sizes/timestamps may vary.

## University evaluator walkthrough

1. Sign in and open Compliance. Select an existing project and Refresh stored results.
   Show actual findings and the versioned OWASP mapped/unmapped counts.
2. Select 2021, inspect a mapped category and open a finding. Explain its CWE/rule,
   finding ID, justification and pinned source. Select 2025 and explain category
   differences without renumbering old findings.
3. Select CIS Docker 1.6.0. Show four supported static checks and eight unsupported
   manual controls. On current local data, explain why all controls are Not Assessed.
4. Open a control: the source timestamp/scan/resource and historical evidence are
   visible when retained; absent evidence remains explicit and retryable.
5. To demonstrate PASS and FAIL without inventing production results, run
   `npm run test:governance:db -w cloudsentinel-backend`. The labeled isolated source
   report contains PASS for DS0002, FAIL for DS0026 and an EXCEPTION interpreted as ERROR.
   Missing controls stay Not Assessed. The test checks those states through real APIs.
   N/A support is demonstrated only by its explicitly labeled future-adapter fixture.
6. Explain 50% pass rate versus 16.67% registered coverage in that fixture; they are
   different from security posture and do not assert certification.
7. In Reports, preserve the chosen scope and download compliance PDF and compliance
   CSV. Compare pass rate, coverage, project/control states and evidence with the UI.
   The isolated integration test also checks this consistency automatically.
8. Explain that a future authorized IaC scan will retain real explicit non-failure
   outcomes, while this task deliberately ran no new scan or deployment.

## Created and modified files for this FE-3 cycle

All paths are relative to the repository root. Earlier uncommitted Module 12 work
remains intact; this list identifies changes made for FE-3 specifically.

| Path | Change |
| --- | --- |
| backend/config/compliance/owasp-cwes.json | New offline published 2021/2025 category/CWE registry with source revision/attribution/license |
| backend/config/compliance/OWASP-LICENSE.txt | New upstream CC BY-SA 4.0 license accompanying adapted metadata |
| backend/config/compliance/cis-docker.json | New versioned 12-control registry, original summaries and exact check references |
| backend/migrations/018_compliance_assessments.sql | New additive capture/target/assessment schema and indexes |
| backend/services/governance/registry.js | Expanded centralized mapping/version/alias engine and provenance |
| backend/services/governance/configuration.js | New sanitized Trivy outcome capture and shared state/aggregation/metric functions |
| backend/services/governance/assessments.js | New mapping refresh, source-evidence persistence, target-aware current/history model |
| backend/services/governance/store.js | Extend existing sync with mapping refresh and assessment import |
| backend/services/governance/query.js | Validate version/benchmark/state filters and OWASP-unmapped selection |
| backend/services/governance/analytics.js | Integrate canonical assessment model; leave posture scoring unchanged |
| backend/services/governance/report.js | Shared metric/evidence PDF content, mapping columns and compliance CSV |
| backend/routes/governance.js | Compliance/control-history APIs, compliance CSV and schema error guidance |
| backend/routes/iac.js | Retain explicit non-failure outcomes; keep them out of vulnerability totals; reject invalid reports |
| backend/routes/sast/compliance.js | Replace obsolete keyword mapper with shared read-only snapshot adapter |
| backend/routes/sast/index.js | Legacy compliance/report endpoints use shared evidence-based model |
| backend/scripts/migrate-governance.js | Add 018 runner and compliance-only mode, preserving 017 |
| backend/scripts/update-owasp-registry.py | New reproducible pinned-metadata maintenance tool |
| backend/scripts/verify-governance.js | Verify both OWASP versions, assessment metrics and duplicate-free real imports |
| backend/package.json | Add migrate:compliance and test:compliance commands |
| backend/test/compliance.test.js | New 16-case FE-3 business-rule and report tests |
| backend/test/governance.test.js | Align regressions with multiple versions and mapping/assessment separation |
| backend/test/governance.integration.test.js | Extend isolated real DB/HTTP workflow for 018, history, states and report consistency |
| frontend/src/components/ComplianceOverview.jsx | New component extending existing compliance view with metrics/versions/control evidence/charts |
| frontend/src/pages/GovernanceDashboard.jsx | Integrate compliance component, dynamic chart version, mapping provenance and fourth export |
| frontend/test/governance.spec.js | Canonical labeled FE-3 fixtures and three extra browser tests |
| docs/fe3-audit.md | New before-change gap assessment |
| docs/fe3.md | This coverage, setup, verification, file inventory and evaluator handoff |
| docs/module12.md | Updated current mapping/assessment architecture, setup, API and requirement status |
| README.md | Link to current FE-3 handoff |

## All-stage compliance correction (18 October 2026)

[Current implementation report](compliance-pipeline-fix.md) supersedes earlier overview
and UI descriptions. OWASP now has evidence-based FAIL/NOT_ASSESSED states and backend
metrics. CIS Controls v8 associations remain separate from Docker Benchmark 1.6.0
assessments. Overall pass rate and coverage use registered project/control slots;
missing evidence never earns PASS. The existing Compliance layout and main dashboard
are preserved. See the report for files, tests, limitations and local verification.

## Final matching/assessment semantics

See [compliance-matching-fix.md](compliance-matching-fix.md) for distinct OWASP X/10,
CIS Controls X/18 and registered Docker X/12 matching counts. The overall supported
assessment rate now uses Docker project-requirement units only; OWASP project-category
states remain separate. This supersedes the earlier 22-slot combined formula and keeps
matching, pass rate and assessment coverage distinct without changing the page design.
