# Module verification on the running stack (2026-11-27)

Live check of Modules 3, 6 and 12, plus the changes from branch `fix/srs-gaps`: Trivy secret scan and stricter
dependency/image gates (SEC-4, Module 9 FE-2), the real Secrets Management screen (FR-20), and resource usage and the
compliance score on the Kubernetes screen (FR-16.2, FR-17.6). Nothing big was fixed in Modules 3, 6 and 12; their gaps
are listed.

## Stack used

| Item | Value |
|---|---|
| Code | branch `fix/srs-gaps` (worktree `~/cs-gaps`), backend on :3000 started with `CS_BACKEND_DIR=~/cs-gaps/backend scripts/start-stack.sh` |
| Engines | ml-sast v3 on :8001, ml-dast v4 on :8002 (both `trained`) |
| Cluster | Minikube, kube context `minikube` (unchanged); metrics-server addon enabled for FR-16.2 (`minikube addons enable metrics-server`) |
| Database | shared CloudSentinel DB; migration 025 (`secret_policies`, additive) applied with `npm run migrate:secrets` |
| Frontend | Vite from `~/cs-gaps/frontend` on http://127.0.0.1:5173 |
| User / projects | existing e2e user; projects 24 (`e2e-node-express`, intentionally vulnerable), 26 (`e2e-python-clean`), 28 (`e2e-node-clean`) |
| AWS | not used |

API checks were made with a short-lived token for the e2e user, created inside a Node process (never printed).

## Screenshot steps (all screens)

1. Open http://127.0.0.1:5173 and log in as the e2e user.
2. Use the left sidebar. Each section below names the sidebar entry, the project to select and what to capture.

## A. Secret scan and stricter gates (SEC-4, Module 9 FE-2)

### What changed

- **Secret scan in the IaC stage.** `trivy fs --scanners secret` runs on the same checkout as `trivy config`
  (`backend/services/secretScan.js`, `backend/routes/iac.js`). Each match becomes a CRITICAL `iac_findings` row with
  `misconfig_id = secret:<rule>`. The matched value and code lines are dropped, so the existing IaC gate (CRITICAL > 0)
  stops the pipeline.
  - **Why the IaC stage:** it already clones the repository and runs Trivy, and its gate reads a single CRITICAL count.
  - **Why not the SAST stage:** that is the ML engine path, whose `scan_results` rows carry the ML model's provenance and
    strict count checks.
- **Neutral working directory.** Both Trivy calls in the IaC stage now run from a neutral directory with an empty ignore
  file.
  - **Why:** a probe with a random fake AWS key showed that, run from inside the repository, the repository's own
    `.trivyignore` / `trivy-secret.yaml` hid both keys (0 found). Run from a neutral directory, both were found as CRITICAL.
- **Gates.** The dependency and image gates (`backend/services/vulnerabilityGate.js`) block **CRITICAL always** and
  **HIGH when a fixed version exists**.
  - Env: `DEPENDENCY_GATE_SEVERITIES` / `IMAGE_GATE_SEVERITIES` (default `CRITICAL,HIGH`) and
    `*_UNFIXED_SEVERITIES` (default `CRITICAL`). An invalid value fails closed.
  - CRITICAL still blocks without a fix, as before. Letting unfixed CRITICAL through would have weakened the gate.
  - The previous rule is `*_GATE_SEVERITIES=CRITICAL`.
- **Correction to PR #28:** a hard-coded secret that ml-sast reports as HIGH (CWE-798) already blocked the pipeline,
  because ML SAST findings are stored as `VULNERABILITY` and the SAST gate blocks HIGH vulnerabilities
  (`backend/services/sastClassification.js`). PR #28 said it did not.

### Results on the real pipeline

| Run | Execution | Result | Detail |
|---|---|---|---|
| python-clean, generated Dockerfile | 120 | **BLOCKED** at the image gate (136 s) | SAST 0, Dependency 0 C/H (3 packages), IaC 0, secrets 0. Image: 0 CRITICAL, 54 HIGH, of which **1 has a fix**: CVE-2026-124851 in `libzstd1` 1.5.7+dfsg-1, fixed in 1.5.7+dfsg-1+deb13u1. The other 53 HIGH have no fix and were ignored as specified |
| node-clean | 121 | **COMPLETED** in 87 s | SAST 0, Dependency 0 (65 packages), IaC 0, secrets 0, image 0 CRITICAL / 0 HIGH (7 MEDIUM, 4 LOW), Deploy, DAST 0 |
| python-clean, fixture Dockerfile on `python:3.13-alpine` | 122 | **COMPLETED** in 33 s | SAST 0, Dependency 0 C/H, IaC 1 LOW (DS026, no HEALTHCHECK), secrets 0, image 0 CRITICAL / 0 HIGH (7 MEDIUM, 4 LOW), Deploy, DAST 1 INFO |
| Manual IaC scan of project 24 (vulnerable fixture) | - | secret found | `secret:github-pat` at `app.js:8`, stored as CRITICAL, value not stored. The IaC gate would stop the pipeline here (SAST blocks this fixture first) |

**How the python-clean block was handled (rule A.3):** I did not weaken the scan; instead I changed the fixture's base
image.

- **Candidates tried:** base images scanned with the pipeline's own Trivy arguments:

  | Base image | OS | CRITICAL | HIGH with fix | Blocks |
  |---|---|---|---|---|
  | `python:3.11-slim` (generated default) | Debian 13.8 | 0 | 1 | yes |
  | `python:3.12-slim` | Debian 13.8 | 0 | 1 | yes |
  | `python:3.13-slim` | Debian 13.8 | 0 | 1 | yes |
  | `python:3.11-alpine` | Alpine 3.24.4 | 0 | 16 | yes |
  | `python:3.13-alpine` | Alpine 3.24.4 | 0 | 0 | no |

- **Fix:** the fixture got its own Dockerfile on `python:3.13-alpine`, pinned by digest, with non-root UID 1000
  (`test-fixtures/cloudsentinel-test-python-clean/Dockerfile`). The same file was pushed to the fixture repository the
  pipeline clones (https://github.com/hammad0-dev/cloudsentinel-test-python-clean, commit `070b419`).
- **Default kept:** both clean fixtures pass, so the default stays CRITICAL + HIGH-with-fix.
- **Remaining limitation:** a Python repository without its own Dockerfile still gets the generated `python:3.11-slim`
  and is blocked until Debian's slim images ship the `libzstd1` fix. The generator itself was not changed.

### Tests

- `backend/test/security-gates.test.js`: 16 tests (gate policy and env, image gate, dependency gate from SBOM rows,
  secret parsing without values, neutral-directory hardening, governance CWE-798 classification).
- Whole backend suite (`npm run test:backend`): baseline 1016 tests, 992 pass, 0 fail, 24 skipped. After all changes:
  **1049 tests, 1025 pass, 0 fail, 24 skipped**. Frontend unit tests: 11/11. `vite build` OK.

## B. Secrets Management screen (FR-20)

**Steps:** sidebar **Secrets**, select project 26 (or 24). Capture the status card, the Secrets table and the Rotation
card.

| Check | Result |
|---|---|
| Hard-coded sample data and dead buttons | removed; the page calls `GET /api/secrets/projects/:id` |
| Project 24 and 26 on Minikube | `observed`, context `minikube`, role `owner`, **0 Secrets** in `cloudsentinel-p-24` / `-26` (the deploy stage creates none) |
| Listing with real kubectl | the same go-template, run read-only on namespace `kyverno`, returned 5 secrets with type, source (TLS certificate / Kubernetes Secret), key count, masked value and last change; no data or key names |
| Rotation card | "Not available on this cluster: minikube has no External Secrets Operator, so no secret here is synced from AWS Secrets Manager. scripts/rotate-secret.sh rotates AWS Secrets Manager secrets; run it against a configured target (an EKS cluster with ESO). The UI does not rotate secrets." |
| Role check | another user's project returns 404 |
| Policy, expiry and the `secret_expiring` alert | **not shown live**: no Secret exists in a project namespace, so no policy can be set. Covered by `backend/test/secrets-management.test.js` (11 tests) |

**To show the policy path in a demo** (creates a Kubernetes Secret, so only with the project owner's consent):

1. Run `kubectl -n cloudsentinel-p-26 create secret generic demo-api-key --from-literal=API_KEY=$(openssl rand -hex 16)`.
2. Reload the screen. Select **Set policy**, enter 30 days and an expiry date within 14 days, then **Save policy**.
3. The expiry badge shows "Expires in N day(s)". Within 15 minutes, a "Secret expiring or expired" alert appears on
   **Monitoring**.
4. Remove it afterwards with `kubectl -n cloudsentinel-p-26 delete secret demo-api-key`.

## C. Kubernetes screen (FR-16.2, FR-17.6)

**Steps:** sidebar **Kubernetes**, select project 26. Capture "Resource usage" and "Policy enforcement" (the score card
is at the top of that panel).

| Check | Result (live) |
|---|---|
| Resource usage (metrics-server) | cluster 1 node: CPU 6894m of 8000m (86.2 %, while the pipeline was building images), memory 3077 of 20002 MiB (15.4 %); project 24 pods 0.7m / 60 MiB, project 26 pods 0.6m / 26.4 MiB |
| Without metrics-server | the panel says "Not available on this cluster: metrics-server is not running on minikube (for Minikube: minikube addons enable metrics-server)" (unit-tested) |
| Compliance score (Kyverno PolicyReports) | project 24: 42 pass / 0 fail = **100 %**; project 26: 91 pass / 0 fail = **100 %** |
| Kyverno missing | "Not available on this cluster: Kyverno is not installed" (unit-tested) |

Tests: `backend/test/kubernetes-usage-compliance.test.js`, 6 tests.

## D1. Module 3: Threat Modeling & Attack Surface Analysis

The SRS (1.7.3) lists FE-1 to FE-7. **Module 3 is not implemented.** There is no threat-model service, route,
table or screen, and the sidebar has no Threat Modeling entry. "Threat modeling" appears only as text on the
Landing, Login and Register pages.

| Req | SRS text | Status | What exists / gap |
|---|---|---|---|
| FE-1 | Generate a high-level architecture model of the application using repository configuration files | partly (indirect) | The EKS generator's analyze step (`backend/services/eksWorkload.js`, Cloud Deployment → infrastructure workflow → Analyze) detects languages, frameworks, databases and the one/two/three-tier layout from repository files. There is no architecture model or diagram for threat modeling |
| FE-2 | Identify system components such as services, APIs, databases, and infrastructure elements | partly (indirect) | The same analyze output lists components (backend, frontend, database client) from declarations; APIs are not identified |
| FE-3 | Apply the STRIDE threat modeling methodology to analyze potential security threats | not met | no STRIDE analysis anywhere |
| FE-4 | Identify attack surfaces including exposed APIs, public network services, and container interfaces | not met | DAST's crawl and the deployment's Service types are recorded, but no attack-surface view is built from them |
| FE-5 | Map identified threats to security controls enforced in the CI/CD security pipeline | not met | - |
| FE-6 | Store threat analysis results in the CloudSentinel governance database | not met | no table |
| FE-7 | Display identified threats and risk levels in the security dashboard | not met | - |

**Screenshot steps:** none for Module 3 itself. For the partial FE-1/FE-2: sidebar **Cloud Deployment**, select a
project, then press **Analyze** in the infrastructure workflow and capture the detected components.

## D2. Module 6: Dependency & SBOM Management

Project 26 after execution 122 (API and screen).

| Req | SRS text | Status | Evidence on the stack |
|---|---|---|---|
| FE-1 | Scan third-party libraries for known vulnerabilities | met | Dependency stage (`backend/routes/dependency.js`, Trivy fs `vuln,license`): 3 packages, 0 CRITICAL/HIGH; project 28: 65 packages, 0 findings. The gate now also blocks HIGH with a fix |
| FE-2 | Scan container images for OS package vulnerabilities | met | image scan in the Deploy stage (`image_scans`): execution 120 blocked (1 fixable HIGH), execution 122 passed (0 CRITICAL / 0 HIGH, 7 MEDIUM, 4 LOW) |
| FE-3 | Generate SBOM for all application components | met | `GET /api/dependencies/sbom/26`: CycloneDX 1.5 JSON download, 4 components, 5642 bytes. Covers application dependencies only, not the container image's OS packages |
| FE-4 | Map detected dependencies to CVE vulnerability databases | met, with a limit | each finding stores its CVE ID, CVSS score and fixed version (`sbom_components`). The dependency DB is pinned offline (downloaded 2026-10-17) and not refreshed, so newer CVEs are missing |
| FE-5 | Provide dependency risk reports | partly | `GET /api/dependencies/report/26` returns a JSON report (project, scans, summary, components, vulnerable). There is no PDF or readable report for dependencies alone; the Module 12 security PDF includes dependency findings |

**Screenshot steps:** sidebar **Dependencies**, select project 26.

1. Capture the scan summary and the component table.
2. Press the SBOM download and save the CycloneDX file.
3. Press the report download (JSON).
4. For the image scan: sidebar **CI/CD Pipeline**, open execution 120 (Deploy failed with the image-gate reason) and
   execution 122 (passed).

## D3. Module 12: Governance, Compliance & Unified Dashboard

| Req | SRS text | Status | Evidence on the stack |
|---|---|---|---|
| FE-1 | Aggregate security results from all scanning modules | met | `POST /api/governance/sync`: SAST, dependency, IaC, image and DAST sources imported (1392 observations on the first sync) |
| FE-2 | Display vulnerabilities and risk levels on the dashboard | met | `GET /api/governance/summary?project=24`: 274 findings (5 CRITICAL, 51 HIGH, 125 MEDIUM, 87 LOW); **Dashboard** screen |
| FE-3 | Map findings to OWASP Top 10 and CIS benchmarks | partly | OWASP Top 10:2021 mapping works: project 24 maps to 4 of 10 categories (A01 6, A03 2, A06 245, A07 1). The CIS Docker benchmark (controls 4.1-4.12) is assessed only when the repository has its own Dockerfile. Projects without one show all 12 as Not Assessed. After execution 122 (fixture Dockerfile), project 26 has 4 assessed (4.1, 4.7, 4.9 PASS; 4.6 FAIL, no HEALTHCHECK), 8 Not Assessed, pass rate 75 %, coverage 33 %. No Kubernetes CIS benchmark |
| FE-4 | Generate security and compliance reports | met | `GET /api/governance/export/{security,compliance,csv,compliance-csv}?project=24`: security PDF 151,624 bytes, compliance PDF 154,482 bytes, findings CSV 275 lines, compliance CSV 13 lines (all valid; PDFs start with `%PDF-`) |
| FE-5 | Provide visual analytics and security score metrics | met, with a caveat | score card and charts on **Dashboard** / **Compliance**. Project 26's posture score is 0 because about 1300 unique unresolved HIGH image findings from earlier runs remain open (history is kept, not reset per run); see the methodology text on the score card |

**Gaps found (not fixed):**

- The filter query parameter is `project`, not `projectId`. An unknown parameter is ignored silently and returns all of
  the user's projects. I made that mistake in my first API calls, and the first unfiltered PDF was 3.4 MB.
- CIS coverage depends on a repository Dockerfile, as described under FE-3.
- Old image findings keep a clean project's score at 0 until they are marked resolved.

**Screenshot steps:**

1. Sidebar **Dashboard**, select project 24: capture severity totals, trend and the score card.
2. Sidebar **Compliance**, select project 26: capture the OWASP table and the CIS Docker controls (4.1/4.7/4.9 PASS,
   4.6 FAIL).
3. Press **Export Readable Report** (PDF) and **Export JSON**.

## Mistakes during this verification

- **Unfiltered first Module 12 calls:** I used `projectId` instead of `project`, so the first Module 12 calls were
  unfiltered. They were repeated with `project=` and only the filtered numbers are used above.
- **Stalled python-clean re-run:** the first re-run never started. Its wait loop used `pgrep -f` on a string that was in
  the loop's own command line, so it waited on itself. It was stopped and run directly (execution 122).
- **Missing node-clean URL:** the first node-clean attempt failed before any execution was created, because
  `E2E_NODE_CLEAN_REPO` is not in the e2e env file. It was re-run with the public fixture URL.
