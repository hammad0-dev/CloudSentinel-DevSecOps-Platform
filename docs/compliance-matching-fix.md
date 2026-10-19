# Compliance matching and assessment correction — 18 October 2026

This report supersedes the combined 22-slot overall formula in
`compliance-pipeline-fix.md`. Existing frontend classes, cards, tables, buttons,
routes, spacing and navigation remain unchanged. No main-dashboard component,
security posture algorithm, authentication rule, scanner execution, database
migration, production lifecycle status, commit or push was changed.

## Root cause

The previous overall 0% was mathematically correct: PASS=0, FAIL=8 in the screenshot.
Those were project-category violations, not eight of ten distinct matched categories.
The frontend bound the OWASP progress bar to assessment pass rate and omitted the
requested distinct-category matching indicator. The CIS card also displayed Docker
assessment metrics under a generic Controls label without a top-level matching count.
The overall aggregation added category violations and Docker requirement outcomes;
the same Docker failure could contribute to both, so those units should not be added.

The source adapters were inspected: SAST, dependency, image and DAST results are
vulnerability observations, not positive whole-category attestations. The IaC adapter
retains explicit Trivy PASS/FAIL/ERROR outcomes using `--include-non-failures` and
`configuration_evidence`, then imports per-target checks. No positive evidence is
being discarded by the assessment calculation. The inspected application database
has zero stored CIS assessment observations. The completed HTML pipeline's IaC scan
has zero Dockerfile targets; its generated Dockerfile is created later at deployment.
Generating that file or passing deployment cannot manufacture a scanned PASS.

## Final metrics and semantics

`compliance.matching` is returned by the existing summary/compliance APIs and JSON
export. It contains `owasp`, `cisControls`, and `docker`, each with named `matched`,
`total`, `percentage`, framework/version and meaning fields.

| Indicator | Formula / scope |
|---|---|
| OWASP category matching | Distinct selected-version category IDs with mapped findings / 10 × 100 |
| CIS Controls matching | Distinct supported CIS Controls v8 association IDs with findings / 18 × 100 |
| Docker requirements with findings | Distinct registered Docker requirement IDs with findings / 12 × 100 |
| OWASP category assessment pass rate | PASS / (PASS + FAIL) project-category slots; null when no slots assessed |
| Supported Docker assessment pass rate | PASS / (PASS + FAIL) project-requirement slots; null when no slots assessed |
| Framework assessment coverage | (PASS + FAIL) / (registered project slots − verified N/A) × 100 |

Matching percentages describe associations, not compliance. Multiple findings or
projects matching A03 count once in X/10; their distinct findings remain in the table.
Resolved/historical associations remain matchable, but only actionable unresolved
violations affect FAIL. OPEN and ACCEPTED_RISK remain actionable; FALSE_POSITIVE and
RESOLVED do not create PASS. Security hotspots/unclassified review findings do not
establish confirmed category failures. Existing CWE/CVE/exact-rule mapping, version
selection, conservative CVE/resource deduplication and source provenance are reused.

`overall` now explicitly identifies its assessment basis as the registered **CIS
Docker Benchmark 1.6.0 project-requirement slots only**. It uses the supported explicit
check outcomes and exact retained requirement failures, not pipeline execution status.
The existing top card is labelled **Docker assessment pass rate**. OWASP assessment
states/rate stay separate in the OWASP card and exports. This avoids averaging
incompatible units or counting overlapping framework associations as independent
checks. A verified positive check with no contradictory open violation changes the
pass count and rate. No checks means Not Assessed, with 0% coverage.

The existing OWASP progress bar now means category matching. The existing CIS progress
bar means CIS Controls matching. Their descriptions/notes retain assessment counts
and pass rates separately. The CIS card describes Docker counts explicitly as
project-control slots; 12 registered requirements are never presented as 18 Controls.
Only three CIS top-level association rules currently exist (CIS-3, CIS-4, CIS-16);
that limited supported mapping scope is exposed in metadata. Neither all 18 Controls
nor the full Docker Benchmark is implemented or certified.

## Actual records verified (read-only)

For project 14, `beginner-html-site-styled`:

- OWASP 2021: **4/10 matched, 40% matching**; 0 passed, 4 failed, 6 unassessed slots.
- CIS Controls v8: **1/18 matched, 5.56% matching**.
- Docker: **0/12 registered requirements with findings**, no positive or negative
  recorded check outcomes; assessment pass rate null, coverage 0%.

For its owner's All projects selection at verification time:

- OWASP: still **4/10**, not 8/30; separate project-category assessments are 0 passed,
  8 failed, 22 unassessed (30 slots across three authorized projects).
- CIS Controls: still **1/18**, not a multiplied denominator.
- Docker: 36 project-requirement slots, all unassessed; null pass rate, 0% coverage.

These are observed records, not hardcoded UI expectations; later scans/reviews can
change them. Other owners' projects remain excluded by existing ownership joins.

## Pipeline integration

| Implemented stage | Stored finding evidence | Positive control outcomes |
|---|---|---|
| SAST | linked `scan_history` / `scan_results` security findings | No whole-OWASP-category positive adapter; successful scan alone is insufficient |
| Dependency / SCA | `dependency_scans` / CVE-bearing `sbom_components` | Inventory/zero CVEs is not an explicit benchmark pass |
| IaC | `iac_scans` / `iac_findings` | Explicit project/target/check outcomes in `configuration_evidence` feed Docker assessments |
| Image | `image_scans` / `image_vulnerabilities` | Vulnerability scan does not assess Docker hardening checks |
| DAST | `dast_scans` / `dast_findings` | Successful job/zero alerts does not establish whole-category PASS |
| Active DAST, when schema exists | stored `active_dast_executions.result.findings` | No compatible positive benchmark adapter |
| Kubernetes audit | Unassigned stored audit | Excluded: records lack project/owner relationship; owned IaC findings still contribute through IaC |
| Secrets management / deployment | No compatible additional finding model | No new scanner or inferred check outcomes |

New results are imported/remapped by the existing stored-result sync. The Compliance
page syncs on entry, project/version changes and every 30 seconds. Summaries/reports
recalculate from database records; no cached percentage is stored. History is retained,
and missing observations do not automatically resolve findings. A retained open exact
Docker violation overrides a later positive check until supported lifecycle review.

## Changed files in this correction

- `backend/services/governance/complianceResult.js`: separate compatible overall Docker
  units from OWASP category assessments; accurate framework-specific methodology.
- `backend/services/governance/assessments.js`: add distinct matching counts and properly
  versioned denominators while retaining project-assessment counts independently.
- `backend/services/governance/report.js`: existing PDF includes X/10, X/18, X/12,
  OWASP assessments and the same supported-check pass rate/coverage as the page.
- `frontend/src/pages/ComplianceDashboard.jsx`: percentage/text bindings only; existing
  cards, bars, table columns, exports and design preserved.
- `backend/test/compliance-pipeline.test.js`: multi-stage/five-findings/duplicate/overlapping
  project matching and positive/negative check assessment regressions.
- `backend/test/governance.integration.test.js`: real owner-scoped API and PDF matching
  assertions, plus existing source, lifecycle, authentication and main-dashboard checks.
- `frontend/test/governance.spec.js`: matching bars, assessment text, JSON exports and
  no-evidence rendering through existing UI.
- `docs/module12.md`, `docs/fe3.md`, this report: current semantics and verification.

No migrations were necessary; 017/018 and source persistence remain unchanged.
Existing legacy API summary fields automatically follow the shared `overall` contract.
The main dashboard's finding totals, filters, all-owner-project scope and posture score
were not modified; only its shared nested compliance payload gains these corrections.

## Executed tests and verification

```bash
node --test backend/test/compliance-pipeline.test.js backend/test/compliance.test.js backend/test/governance.test.js backend/test/sast-classification.test.js backend/test/sast-evidence.test.js backend/test/sast-gate.test.js backend/test/sast-gate-counting.test.js backend/test/sast-linkage-contract.test.js backend/test/unified-report.test.js backend/test/dependency-runtime.test.js backend/test/kubernetes-security.test.js backend/test/project-webhook-secret-exposure.test.js frontend/src/utils/executionReport.test.js frontend/src/utils/executionScan.test.js
npm run test:governance:db -w cloudsentinel-backend
npm run test:governance -w cloudsentinel-frontend
npm run build -w cloudsentinel-frontend
```

The unit/regression suite contains 102 tests. The isolated PostgreSQL/JWT HTTP workflow
verifies six source adapters, repeat imports, source traceability, explicit PASS/FAIL,
contradictory failures, no-evidence null rate, independent coverage, owner isolation,
selected/all-project scope, multiple owned projects with findings and a foreign owner's
project, legacy API, PDF/CSV consistency and matching denominators. The nine Chromium
tests verify existing main dashboard charts/filters, project selection, framework
version, matching bindings, assessment values, PDF/JSON downloads and mobile layout.
PDF text is decoded to compare matching counts with API data; JSON download contents
are compared with the exact summary metrics. Fixture records are isolated in a temporary
schema and removed; browser fixtures are not application evidence.

Initial unit assertions still expected the former mixed-unit overall rate; they were
updated to assert separate OWASP failures and null Docker rate when no Docker checks
exist. No production findings or lifecycle states were changed to make tests pass.
The existing Vite large-chunk warning remains; bundle restructuring is outside scope.

## Local verification

Restart the existing backend (`cd backend && npm run dev`) after stopping its prior
process, then refresh Compliance. Select `beginner-html-site-styled` and compare the
observed metrics above; select All projects and verify unique X/10 and X/18 denominators.
Export PDF and JSON at the same scope/version to compare matching and assessment data.
Open Dashboard without a project filter to retain its all-authorized-project view.
No scan, deployment or database migration is required for this display correction.
