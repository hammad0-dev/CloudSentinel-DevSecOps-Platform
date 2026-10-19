# Compliance pipeline calculation correction — 18 October 2026

This handoff supersedes the earlier compliance UI and calculation descriptions in
Module 12 / FE-3 where they differ. The existing page layout, cards, columns,
selector, export buttons, navigation, theme and main dashboard were preserved.
No scanners, active attacks, deployment, AWS changes, migrations, commits or pushes
were run for this change.

## Root cause and inspected contracts

The actual `store.js` already imports six project-owned scanner sources. The bug
was not a missing SAST-only SQL union: `buildCompliance` exposed OWASP association
counts without category assessment states, and the UI calculated its own mapping
coverage/verified-credit percentages. Those were different from backend benchmark
pass rate and PDF values. Exact Dockerfile mappings were the only CIS associations.
Unresolved historical violations could be contradicted by newer positive checks.
Older descriptions of 10/10 passed / 15/18 passed are not supported by current
explicit-evidence records and must not be restored.

The main dashboard uses `/governance/summary`, `selection` / `scope` owner joins,
and an optional project filter; absent that filter it includes all authorized
projects. Its finding totals, charts, posture `score()` and frontend are unchanged.
Only the nested compliance response gains corrected/additive data. Project-specific
compliance requests never change session state or the main dashboard scope.

## Actual stage integration matrix

| Implemented source | Stored findings | Integrated | Evidence source |
|---|---|---|---|
| SAST | Yes | Yes | `scan_history` / linked `scan_results`; bugs and code smells excluded; unreviewed hotspots remain review observations |
| Dependency/SCA | Yes | Yes | `dependency_scans` / `sbom_components` with CVE; inventory-only rows excluded |
| IaC / Dockerfile config | Yes | Yes | `iac_scans` / `iac_findings`; `configuration_evidence` retains explicit Trivy outcomes |
| Container image | Yes | Yes | `image_scans` / `image_vulnerabilities`; completed and vulnerability-blocked scans imported |
| DAST | Yes | Yes | `dast_scans` / `dast_findings`, stored CWE when present |
| Active DAST | Conditional | Yes when installed | `active_dast_executions.result.findings`; unavailable schema remains unavailable |
| Kubernetes audit | Yes, unassigned | No independent adapter | `kubernetes_scans` persistence lacks project/owner identity; no ownership inferred. Project-owned Kubernetes IaC findings already enter via IaC |
| Secrets page | No compatible security-finding store | No | Secrets management UI is not a project-linked secret-detection scanner |
| Cloud / deployment | Execution results | No fabricated findings | Successful deployment is not vulnerability or compliance evidence |

Existing source adapters, normalized persistence, migrations 017/018 and original
scanner observations remain intact. Refresh remaps retained findings even if original
source detail was removed. It never resolves findings automatically.

## Mapping, lifecycle and deduplication

All supported stages use the existing pinned OWASP 2021/2025 CWE registry, exact
Dockerfile rule aliases, and justified dependency/image component CVE associations.
Version-specific IDs are never renumbered mechanically. Unknown identities remain
unmapped; code smells and unconfirmed review classifications cannot establish a
confirmed failed category.

Explicit internal CIS Controls **v8 associations** are separate from the Docker
Benchmark **1.6.0** registry:

- CIS-16: confirmed vulnerability classification from SAST, dependency, image,
  DAST or active DAST, with an explicit CVE/CWE reference.
- CIS-4: one of the four recognized exact Dockerfile misconfiguration checks.
- CIS-3: explicit CWE-200/201/312/319/321/798 data-protection references.

These maintained association rules identify `CONTROL_GAP` for actionable unresolved
findings. They are not an official CIS crosswalk, whole-control FAIL/PASS, or a
benchmark assessment. References: [CIS Controls v8](https://www.cisecurity.org/controls/v8)
and the existing pinned Trivy/Docker profile documented in `fe3.md`.

Compliance-only deduplication groups an exact CVE plus exact affected resource and
project across sources. A shared CWE/rule never collapses separate vulnerabilities.
Distinct image tags, paths, versions and projects stay separate. When resources
cannot be verified as identical, records remain separate; package identity alone
cannot establish that a deployed image and a source dependency are the same asset.
Source member IDs, scanner/scan IDs, observation times and lifecycle remain traceable.
The durable source-aware finding identity and main dashboard counts are unchanged.

OPEN and ACCEPTED_RISK remain violations. RESOLVED and FALSE_POSITIVE no longer
contribute violations but do not themselves prove PASS. A retained open exact
Dockerfile violation overrides a newer positive check until reviewed. No automatic
resolution is inferred from a later scan omission. Historical views retain current
reviewed lifecycle; historical lifecycle reconstruction is not implemented.

## One calculation, separate denominators

Each authorized project contributes ten selected-version OWASP category slots and
twelve registered Docker Benchmark control slots. Actual verified N/A removes a
slot from applicability. OWASP categories FAIL on unresolved mapped violations;
otherwise NOT_ASSESSED because no supported whole-category positive adapter exists.
Benchmark states retain per-target explicit evidence aggregation; unresolved exact
requirement violations override PASS. Eight manual Docker controls remain unsupported.

```
assessed = PASS + FAIL
applicable = registered slots - verified NOT_APPLICABLE
passRate = PASS / assessed * 100      # null if assessed == 0
coverage = assessed / applicable * 100
```

The overall response counts registered assessment slots directly; it does not average
OWASP and CIS percentages or apply invented severity weights. It is labelled
**compliance pass rate**, accompanied by coverage and limitations, not a formal
certification score. Unmapped findings remain visible and never earn positive credit.
A pass rate of 100% on a partially assessed subset is not full compliance: the separate
coverage and unassessed counts identify that limit. No assessments means Not Assessed.
The separate security posture algorithm is unchanged.

Project/source/date select assessment scope. Severity/status/search/mapping filters
can select table counts but cannot hide violations from assessment calculations.
The Compliance page currently requests project and OWASP version only, ensuring the
whole selected project's supported sources contribute.

## Files and API/export contract

Backend changes:

- `backend/services/governance/complianceResult.js`: compliance-only deduplication,
  lifecycle handling, project/category and benchmark violation states, overall metrics.
- `backend/services/governance/assessments.js`: reuse all-source dataset, expose category
  states, CIS Controls associations, severity counts, corrected benchmark/current/gap
  states and overall result; assessment filters do not remove contradictions.
- `backend/services/governance/registry.js`: explicit versioned CIS Controls associations.
- `backend/services/governance/report.js`: same backend overall/category/association
  data in existing compliance PDF; benchmark CSV retains corrected assessment metrics.
- `backend/routes/sast/index.js`: legacy compliance summary keys use shared overall
  pass rate and coverage rather than a conflicting benchmark-only score.

Minimal frontend changes: `frontend/src/pages/ComplianceDashboard.jsx` only binds
existing percentages, counts, description text and CIS table to backend results.
No styling, spacing, layout, columns, button, navigation or component replacement.
JSON export already serializes the same summary; PDF requests the same project/version.
No new endpoint or database migration was needed.

Tests: `backend/test/compliance-pipeline.test.js`,
`backend/test/governance.integration.test.js`, `frontend/test/governance.spec.js`.

Additive response fields under `compliance`: `overall`, `owaspMetrics`,
`owaspProjectCategories`, `cisControls`, `uniqueVulnerabilities`, `sourceObservations`.
Existing `metrics` remains Docker benchmark metrics; `cis` remains benchmark controls.
The existing table labelled CIS Controls now binds only to `cisControls`; benchmark
states remain in the existing assessment details. Source-level main-dashboard totals
and compliance-deduplicated totals are intentionally distinguishable.

## Executed validation

- `node --test backend/test/compliance-pipeline.test.js backend/test/compliance.test.js backend/test/governance.test.js`: 33 tests.
- `npm run test:governance:db -w cloudsentinel-backend`: isolated PostgreSQL / real
  JWT HTTP workflow covering six adapters, two authorized projects, another owner,
  unauthenticated 401, unauthorized project 404, selected vs all-project scope,
  repeat ingestion, lifecycle, contradictory PASS, PDF/CSV and legacy consistency.
- `npm run test:governance -w cloudsentinel-frontend`: 9 browser tests; backend metric
  binding, no-evidence display, project scope, exports, versions, existing main dashboard,
  finding review, error recovery and mobile layout.
- Scanner/report regression command recorded below: 67 tests.
- `npm run build -w cloudsentinel-frontend`: passes; existing Vite large-chunk warning.

The new contradiction test initially exposed an older test expecting a fresh PASS
while a historical violation remained OPEN. The fixture now first verifies FAIL,
then performs an explicit owner resolution and verifies the positive assessment.
No production lifecycle was changed. No unresolved failure remains in executed tests.

Regression command:

```bash
node --test backend/test/sast-classification.test.js backend/test/sast-evidence.test.js backend/test/sast-gate.test.js backend/test/sast-gate-counting.test.js backend/test/sast-linkage-contract.test.js backend/test/unified-report.test.js backend/test/dependency-runtime.test.js backend/test/kubernetes-security.test.js backend/test/project-webhook-secret-exposure.test.js frontend/src/utils/executionReport.test.js frontend/src/utils/executionScan.test.js
```

## Local verification

1. Stop the existing backend with Ctrl+C and restart with `cd backend && npm run dev`.
2. Refresh Compliance. Existing page entry sync imports/remaps stored evidence only.
3. Choose a project; compare OWASP states, CIS association counts, benchmark assessment
   details, pass rate, coverage and unmapped findings. Change project and compare again.
4. Export Readable Report and JSON with the same selection/version; their overall
   result, category states and control associations must match the page.
5. Open Dashboard via its navbar entry without a project filter: authorized all-project
   totals and unchanged security posture remain. No new scan is needed for verification.
