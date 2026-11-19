# CloudSentinel — Claude guide

## Stack
- Backend: Node.js + Express (`backend/`), PostgreSQL (`schema.sql` + `backend/migrations/`), Trivy (deps/IaC/image).
- Frontend: React 18 + Vite + Tailwind (`frontend/`), Playwright tests.
- Run backend: `cd backend && npm install && npm run dev` (needs `backend/.env`, see `.env.example`).
- Run frontend: `cd frontend && npm install && npm run dev`.
- DB: `psql -d cloudsentinel -f schema.sql`, then `npm run migrate:governance` / `migrate:compliance` / `migrate:sast` in `backend/`.
- Tests (backend): `npm run test:governance`, `npm run test:compliance`; DB-backed: `npm run test:governance:db`, `npm run test:sast:db`.
- Tests (frontend): `npm run test:governance` (Playwright). There is no plain `npm test`.

## Scope (decided)
- Target apps: Python and Node.js only.
- SAST and DAST engines are being replaced by trained ML services `ml-sast` and `ml-dast`
  (Python/FastAPI, code in `/ml` and `/services-ml`), selected via `SAST_ENGINE` and `DAST_ENGINE` flags.
- Trivy (dependency/image), IaC scanning and governance/compliance stay as they are.

## Rules
- Legacy ZAP/Sonar code is frozen (tag `legacy-zap-dast`). Do not extend `backend/services/zap*`,
  `backend/services/active*`, `c19b*` files, or related docs.
- Every task must map to a requirement FE-x of Modules 1-12; record it in `docs/traceability.md`.
- One module per branch, small commits, never push to `master` directly.
- Never commit `.env`, DB dumps, or `*.orig` files.

## Findings contract (stage -> governance)
Orchestrator calls `POST /api/{sast|dependencies|iac|dast}/scan/{projectId}` (pipeline JWT) and reads
`res.data.summary`. The gate then requires a `COMPLETED` scan row linked by `pipeline_execution_id`
with severity counts (`critical`, `high`, `medium`, `low`, `total_issues`/`total_findings`).
Governance (`services/governance/store.js` + `normalize.js`) reads detail rows from
`scan_results` (SAST) and `dast_findings` (DAST) and normalizes them to:

```json
{
  "source": "SAST | DEPENDENCY | IAC | IMAGE | DAST | ACTIVE_DAST",
  "identity": "rule / CVE / misconfig_id / plugin_id",
  "title": "string",
  "description": "string",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO | UNKNOWN",
  "location": "file:line | pkg:name@ver | METHOD endpoint param",
  "remediation": "string",
  "references": ["CWE-89"],
  "classification": "VULNERABILITY | HOTSPOT_REVIEW | UNCLASSIFIED_REVIEW | MISCONFIGURATION",
  "fingerprint": "sha256(project_id, source, identity, location)",
  "mappings": "from registry.mapFinding",
  "evidence": { "sourceTable": "", "sourceRecordId": "", "scanId": "", "scanMode": "",
                "rule": "", "originalSeverity": "", "issueType": "", "hotspotReview": "" }
}
```
ML SAST rows must supply: `id, rule, message, file_path, line_number, severity, issue_type
(VULNERABILITY|SECURITY_HOTSPOT), hotspot_review`. ML DAST rows: `id, plugin_id|attack_type|alert,
alert, severity, method, endpoint, param, solution, cwe_id`.
