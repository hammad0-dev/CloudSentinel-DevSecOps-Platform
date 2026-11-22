# ML engines as the default: report

Branch `feat/ml-default-engines` (worktree `~/cs-engines`, from `origin/master` at `ebfd9a8`). Date 2026-11-22.

**Requirement (supervisor):** SAST and DAST use our own trained ML models: ml-sast v3 on port 8001 and ml-dast v4
on port 8002. SonarQube and ZAP must not be needed to run the pipeline.

## Plain-language summary

- **ML is now the default.** The pipeline uses our own models unless someone explicitly asks for the old tools.
  - SAST: `ml-sast-v3-ensemble` 3.0.0.
  - DAST: `ml-dast-lr` 4.0.0.
- **SonarQube and ZAP are not needed.** Both e2e apps ran with no SonarQube and no ZAP present anywhere:
  - `python-clean` passed every stage, including deploy and DAST.
  - `demo-forms` was blocked at SAST with 6 ML findings, as expected for the deliberately vulnerable app.
- **No silent fallback.** If an ML service is down, broken or not configured, the stage fails. The message names
  the service and its URL, for example:
  `ML SAST service at http://127.0.0.1:8999 is unreachable (ECONNREFUSED). Start the service; the stage does not fall back to another engine.`
- **The old tools still exist, as an explicit opt-in.** They are marked "legacy, benchmark only". No code was
  deleted. Full removal is possible, but needs one refactor first (see Risks).
- **Every scan records what produced it.** New ML scans store the engine plus the model name, version and SHA-256.
  Old scans were not changed.

## What changed

| Area | Change |
|---|---|
| Engine defaults | `SAST_ENGINE` and `DAST_ENGINE` default to `ml`; an unset or blank flag means `ml`. `sonar` / `zap` are accepted only when set explicitly, and the error text calls them "legacy, benchmark only". |
| Fail closed | The ML route paths already had no fallback; this is now covered by tests. The "unreachable" message no longer says "switch the engine flag back". Unreachable, timeout, HTTP error, invalid response and unset URL all fail the stage. |
| SonarQube off the default path | The SAST results page (`GET /api/sast/:id`) and the report (`GET /api/sast/report/:id`) fetched SonarQube metrics on every load. They now do so only with `SAST_ENGINE=sonar`. |
| Provenance | `scan_history` rows are created with `scan_engine` (`ml` or `sonar`). The SAST results API returns `engine: {name, legacy, model: {name, version, sha256}}`. The DAST API returns `scan_engine`, plus the existing `policy_name`/`policy_version` (the ML model name and version). |
| Timeout | `ML_SAST_TIMEOUT_MS` code default changed from 300 s to 1,800 s. ml-sast v3 runs CodeBERT on CPU; 1,800 s matches the orchestrator's stage timeout and the value already in your `.env`. |
| Migration | New `npm run migrate:engines` applies migration 023 (`scan_engine`, `tool_provenance`; idempotent). The default path now needs it. |
| Config | `backend/.env.example`: `SAST_ENGINE=ml`, `DAST_ENGINE=ml`, URLs `127.0.0.1:8001/8002`. `SONAR_*` moved into an optional, commented "legacy" block. |
| Setup checks | `wsl2-setup/verify-migration.sh` checks ml-sast and ml-dast. Its SonarQube, `SONAR_HOST`/`SONAR_TOKEN` and sonar-scanner checks run only with `SAST_ENGINE=sonar`. `step2c-postgres-setup.sh` no longer asks for a Sonar token. |
| Frontend | SAST page header shows the engine and model (e.g. `ML SAST · ml-sast-v3-ensemble 3.0.0`); ML rules link to their CWE page instead of a broken SonarSource link. DAST page header, banners and footer show `ML DAST · ml-dast-lr 4.0.0` instead of "OWASP ZAP"; legacy rows show `<policy> (legacy)`. |
| Docs | `docs/ml-architecture.md` (defaults, no-fallback rule, provenance, migration, legacy section, measured comparisons only), `README.md`, `backend/README.md`, `docs/traceability.md` (new row; ML rows now say default `ml`). |

Docker Compose and start scripts: the repository has no docker-compose file. `scripts/run-ml-*.sh` never started
SonarQube or ZAP. The backend does not check SonarQube or ZAP at startup, and its health check never did. The only
other SonarQube start hint was in `verify-migration.sh`, which is now legacy-only.

### Files touched

- **Backend:**
  - `backend/services/ml/{engines,mlHttp,mlSastClient}.js`
  - `backend/routes/sast/index.js`, `backend/routes/dast.js`
  - `backend/scripts/migrate-engines.js` (new), `backend/package.json`, `backend/.env.example`
- **Tests:** `backend/test/ml-engines.test.js`, `backend/test/commissioning-static-isolation.test.js`
- **Frontend:** `frontend/src/utils/scanEngine.js` (new), `frontend/src/pages/{SASTResults,DASTResults}.jsx`
- **Setup:** `wsl2-setup/{verify-migration,step2c-postgres-setup}.sh`
- **Docs:** `README.md`, `backend/README.md`, `docs/{ml-architecture,traceability,ml-default-engines-report}.md`

Stored data: no row was rewritten. Rows with a NULL `scan_engine` predate the column. The SAST API shows them as
`sonar` (legacy). ZAP rows keep NULL and their ZAP `policy_name`.

## Tests

| Suite | Result |
|---|---|
| `npm run test:ml` (backend ML engines) | **25 / 25 pass** (was 23; 2 new tests, 3 rewritten) |
| `npm run test:governance` | **12 / 12 pass** |
| `npm run test:compliance` | **16 / 16 pass** |
| All backend `test/*.test.js` | **935 pass, 23 fail**. The 23 failures are identical to unchanged `master` (933 pass, 23 fail) |
| Frontend `vite build` | passes |
| Frontend Playwright (`npm run test:governance`) | **not run**: Playwright needs Node 20; this machine has Node 18.20.8 |

**New and rewritten tests** (`backend/test/ml-engines.test.js`):
- **(a) Defaults are ml.**
  - Flags default to `ml`, including blank values.
  - `sonar`/`zap` are accepted; other values are rejected.
  - The ML SAST timeout defaults to 1,800 s.
- **(b) Service down means the stage fails, with no fallback.**
  - SAST and DAST routes on the default engine: unreachable service gives 5xx with service and URL; HTTP 500 from
    the service fails; unset `ML_DAST_URL` fails.
  - The scan row ends `FAILED`, and the Sonar/ZAP stubs are called **0** times.
  - The SAST results API never asks SonarQube for metrics by default.
- **(c) The sonar/zap opt-in still works.**
  - `SAST_ENGINE=sonar` reaches the SonarQube adapter and stores `scan_engine=sonar`.
  - `DAST_ENGINE=zap` reaches the ZAP baseline adapter.
  - `SAST_ENGINE=sonar` still returns SonarQube metrics.
  - `commissioning-static-isolation.test.js` exercises the Sonar adapter, so it now sets `SAST_ENGINE=sonar` explicitly.

**Known failing backend tests (unchanged, not touched): 23 failures in 8 files.** These fail identically on `master`.

| File | Failures |
|---|---|
| `test/native-connect-artifact.test.js` | 7 |
| `test/gateway-integration.test.js` | 4 |
| `test/same-socket-connect.test.js` | 4 |
| `test/deployment-eligibility.test.js` | 3 |
| `test/provenance-recovery.test.js` | 2 |
| `test/pipeline-provenance.test.js` | 1 |
| `test/scan-evidence-retention.test.js` | 1 |
| `test/zap-containment-diagnostic.test.js` | 1 |

## Verification (e2e, no SonarQube or ZAP)

**Setup:**
- Temporary backend on port 3100, running the code from this branch with `BACKEND_ENV_FILE` set to the real
  backend `.env` (not printed or copied).
- `SAST_ENGINE`, `DAST_ENGINE` and `ML_SAST_TIMEOUT_MS` were blanked, so the code defaults applied.
- `SONAR_HOST` was set to a dead port, `SONAR_TOKEN` blanked, and `ZAP_IMAGE` set to an image that does not exist.

**Before and after the runs:**
- The only SonarQube container had exited 2 days earlier.
- No ZAP container or process was running.
- No SonarQube or ZAP container runs inside Minikube.

The services on 8001, 8002 and 3000 were not touched.

**python-clean** (execution 107): **COMPLETED in 37 s, gate passed**

| Stage | Result | Time |
|---|---|---|
| SAST (ml-sast-v3-ensemble 3.0.0) | 0 findings | 4.3 s |
| Dependency | 1 low | 2.5 s |
| IaC | 0 | 1.7 s |
| Image + Deploy to Minikube | Image 234 findings (not gated); Deploy SUCCESS | 27.8 s |
| DAST (ml-dast-lr 4.0.0) | 1 informational (missing X-Content-Type-Options) | 0.2 s |

**demo-forms** (execution 108): **blocked at SAST in 6 s**

- SAST: 6.2 s, 2 CRITICAL SQL injection (`app.py:50`, `:92`) and 4 HIGH XSS (`:73`, `:84`, `:110`, `:119`).
- All findings are `ml:` rules. `:119` is in the app's `feedback_safe()` example, a known false positive (see the
  ml-sast model card).

**Wrong ml-sast URL** (`ML_SAST_URL=http://127.0.0.1:8999`, execution 109):

- The pipeline ended with status `ERROR` after 63 s: two attempts plus the orchestrator's standard 60 s retry.
- `failure_reason`: `Stage SAST failed after 2 attempts: ML SAST service at http://127.0.0.1:8999 is unreachable (ECONNREFUSED). Start the service; the stage does not fall back to another engine.`
- Nothing after SAST ran. SonarQube was not contacted.
- Both attempt rows are stored as `FAILED` with `scan_engine=ml`.

**Stored provenance** (read from the database):

| Execution | Table | Engine | Model | Version | SHA-256 |
|---|---|---|---|---|---|
| 107 | scan_history | ml | ml-sast-v3-ensemble | 3.0.0 | f28cc42b…c954f |
| 108 | scan_history | ml | ml-sast-v3-ensemble | 3.0.0 | f28cc42b…c954f |
| 107 | dast_scans | ml | ml-dast-lr | 4.0.0 | 7a306aca…67322 |

Item 4 of the brief (the backend already recorded provenance for ML scans) is verified. Two gaps were fixed:
- the opt-in Sonar path stored no engine;
- the APIs did not return the engine and model to the UI.

## Removed from the default path vs kept

**Removed from the default path:**
- SonarQube and ZAP as defaults.
- SonarQube metric calls on the SAST results page and report.
- `SONAR_*` as expected settings in `.env.example`.
- The SonarQube and sonar-scanner checks in `verify-migration.sh`.
- The Sonar-token step in `step2c`.
- "OWASP ZAP" / "SonarQube" as the engine name in the UI.

**Kept, explicit opt-in only, marked legacy, benchmark only:**

| Opt-in | Code | Needs |
|---|---|---|
| `SAST_ENGINE=sonar` | Sonar parts of `backend/routes/sast/{index,config,pipeline,metrics}.js`, `backend/services/{sonarAnalysisProvenance,sonarIssueEvidence}.js` | SonarQube server, sonar-scanner, `SONAR_HOST`, `SONAR_TOKEN` |
| `DAST_ENGINE=zap` | `runBaselineScan` in `backend/services/dastBaselineScanner.js` | Docker, ZAP image |
| `DAST_ACTIVE_ENABLED=true` (off by default; frozen, tag `legacy-zap-dast`) | active-DAST / ZAP subsystem | ZAP image, commissioning setup |

Nothing was deleted.

## Risks

1. **ML DAST depends on the ZAP baseline module.**
   - `services/ml/mlDastScan.js` imports `authorizeTarget`, `persistCompletedScan`, `summarize` and `fingerprint`
     from `services/dastBaselineScanner.js`.
   - The default DAST route uses `baselineTarget` from `services/activeDastPrerequisites.js`, a file in the frozen
     active-DAST group.
   - Deleting the legacy files as they are would break ML DAST.
2. **Provenance-bound STATIC_HTML executions** (`PIPELINE_PROVENANCE_ENABLED`) need SonarQube/ZAP-specific evidence.
   - Under the ML default they fail closed with `ML_ENGINE_PROVENANCE_UNSUPPORTED` (HTTP 409); the message names the
     legacy flags.
   - This setting is not in your `.env`, so today's pipeline is not affected.
3. **Migration 023 is now required.**
   - New SAST rows write `scan_engine`, and the DAST API reads it.
   - Your database already has it, since ML scans have run. A fresh database needs `npm run migrate:engines` after
     `schema.sql`.
4. **The legacy adapters are tested only against mocks.**
   - No real SonarQube/ZAP run was made here, and they will drift over time.
   - They never run by default, so the runtime risk is low.
   - The maintenance cost is real: the frozen active-ZAP group alone is 23 service files (about 2,100 lines),
     14 scripts/config files and 28 test files.
5. **ML service URLs have no code default.**
   - An unset `ML_SAST_URL`/`ML_DAST_URL` fails the stage (deliberately fail-closed).
   - `.env.example` and the e2e setup set them.
6. **No accuracy comparison with SonarQube exists.**
   - `services-ml/ml-sast/reports/comparison.json` records that no SonarQube results were available.
   - The only ZAP comparison on a held-out set (`services-ml/ml-dast/reports/zap_comparison_v4_final.md`) is one app
     (DVPWA) and 8 endpoint-parameters: ml-dast − ZAP macro-F1 +0.125, 95% CI [+0.000, +0.436]. That cannot show
     a difference.
   - Accuracy claims belong to the model cards.

**Proposed full removal (not done; for a separate PR, if you want it):**

- **A. SonarQube SAST adapter**
  - Delete `backend/routes/sast/metrics.js`, `backend/services/sonarAnalysisProvenance.js` and
    `backend/services/sonarIssueEvidence.js`.
  - Delete the Sonar functions in `routes/sast/config.js` (`sonarBaseUrl`, `sonarOrganizationArgs`,
    `sonarAuthAxiosConfig`, `assertSonarReachable`, `allowEmptySonarIndex`, `shouldUseSonarBranchAnalysis`,
    `SONAR_*` timeouts) and in `routes/sast/pipeline.js` (`runSonarScannerAsync`, `stripSonarProjectPropertiesFromClone`,
    and the Maven/Gradle builds that exist only for Sonar Java).
  - Delete the Sonar branch of `routes/sast/index.js` and the `sonarMetrics` UI panel.
  - Delete `test/sonar-issue-evidence.test.js` and `test/sonar-organization.test.js`.
  - Consequence: provenance-bound STATIC_HTML executions would have no SAST engine.
- **B. ZAP baseline adapter**
  - First move `authorizeTarget`, `persistCompletedScan`, `summarize`, `fingerprint` and `extractFindings` into a
    shared module (e.g. `services/dastFindings.js`).
  - Then delete `runBaselineScan` and the ZAP/Docker settings from `dastBaselineScanner.js`, plus the `zap` flag value.
  - Adapt `test/dast-baseline-scanner.test.js`.
- **C. Frozen active-ZAP subsystem** (tag `legacy-zap-dast`)
  - **Services:** `backend/services/{activeDastCommissioning,activeDastEvidence,activeDastGrants,activeDastPrerequisites,activeDastReadiness,activeDiagnosticAuthorization,activeOperatorEnrollment,activeRuntimeArtifacts,activeRuntimeRegistry,activeScannerBinding,activeSquidPolicy,activeTargetEnrollment,activeZapRuntime,dastActiveScanner,module2ActiveDast,zapAutomationEvidence,zapCommissioningTraffic,zapContainmentDiagnostic,zapDiagnosticBudget,zapDispatchEvidence,zapInitialization,zapStartupEvidence,zapStartupLog}.js`.
    Keep `baselineTarget` from `activeDastPrerequisites.js` by moving it first.
  - **Scripts and config:** `backend/scripts/{assemble-zap-image.py,zap-containment-diagnostic.js,zap_capability_diagnostic.py,zap_commissioning_probe.py,zap_diagnostic_inspection.py,zap_runtime_diagnostic.py,zap_writable_runtime.py}`,
    `backend/config/{active-runtime-artifacts.json,active-zap-image-manifest.json,zap-active-policy-v1.conf,zap-active-policy-v1.json,zap-containment-diagnostic.json,zap-diagnostic-contracts.json,zap-writable-paths.json}`.
  - **Tests:** the 28 `test/{active-*,dast-active-scanner,module2-active-*,zap*}` test files.
  - **Orchestrator:** the `DAST_ACTIVE_ENABLED` branch.
  - **Frontend:** `HistoricalDastDiagnostics`.
  - This touches the commissioning subsystem and the FE rows that reference it. It needs your decision and its own
    traceability entries.

## What you must do after merging

1. **Update `~/CloudSentinel`.** Run `git pull` on `master`, then `cd backend && npm run migrate:engines`. It is
   idempotent, and your database already has the columns, so it makes no change.
2. **Leave `backend/.env` as it is.**
   - The explicit `SAST_ENGINE=ml`, `DAST_ENGINE=ml`, `ML_SAST_URL`, `ML_DAST_URL` and `ML_SAST_TIMEOUT_MS=1800000`
     lines stay valid.
   - The `SONAR_*` lines are now unused unless you opt into the legacy engine. You can delete them or keep them.
3. **Restart with `~/cs-sast/scripts/start-stack.sh --restart`.** No change is needed for the new defaults:
   - It checks that `.env` contains `SAST_ENGINE=ml`, `DAST_ENGINE=ml`, both URLs and `ML_SAST_TIMEOUT_MS=1800000`.
   - Those checks still pass with your `.env`. They are stricter than needed now that `ml` and 1,800 s are code
     defaults.
   - If you ever remove those lines from `.env`, the script stops with "backend/.env needs: …". It is not broken; a
     later change could accept missing values as the defaults.
4. **`start-stack.sh` is not in `master`.**
   - Its commit (`ad4d388`) was pushed to `feat/ml-sast-v3` after PR #19 had been merged.
   - The file exists only in `~/cs-sast`, which is where you run it from, so this works.
   - To have it in the repository, open a small PR that cherry-picks `ad4d388`.
5. **Optional: run the frontend Playwright suite** (`cd frontend && npm run test:governance`) on a machine with
   Node 20.
