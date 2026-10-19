# FE-3 audit — 18 October 2026

Existing worktree contains the previous Module 12 implementation; preserve it.
Inspected governance registry/normalizer/import/query/analytics, routes, report service,
UI and tests; migrations 007–017, IaC persistence, Kubernetes audit, deployment
validation, authentication and project ownership. Baseline verification reproduced:
69 unique findings, zero repeat-import observations, posture 7/100, detail slots10/20.

Gaps:
- OWASP 2021 has only a small manually curated CWE subset and no version selector.
  OWASP's official repository now publishes 2025 final. Keep 2021 and add2025
  independently, using pinned published category/CWE lists; no ID renumbering guesses.
- CIS Docker1.6.0 has three registry entries, two failure-only checks; summaries
  conflate finding mappings with assessments. No target/check history, pass-rate,
  coverage denominator or evidence drill-down.
- Trivy's official Docker1.6.0 profile supports four configuration checks:
  DS0002/4.1, DS0026/4.6, DS0017/4.7, DS0005/4.9. Other image/build controls need
  evidence not currently captured. Register them as unsupported/manual, not passed.
- Existing IaC execution is project-owned and can emit non-failure results via
  --include-non-failures, but currently saves only failures and deletes older rows.
  Capture sanitized check outcomes on the scan; do not execute scanners for this task.
- Kubernetes audit rows have no owner/project/target identity and may contain fallback
  issues. Deployment success also lacks retained configuration proof. Do not backfill
  ownership or derive CIS passes from either. Kubernetes/Linux benchmark coverage
  remains explicitly unavailable; IaC manifest checks alone do not establish a
  versioned cluster/host benchmark assessment.
- Legacy /sast/compliance still invents passed controls from missing categories;
  route it through the shared governance assessment calculations for compatibility.
- Reports/UI need versioned categories, actual target assessment statuses, history,
  supporting evidence and shared calculations. Preserve existing security score.
