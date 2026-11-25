# End-to-end pipeline test on the local stack (Minikube staging)

Run on 2026-11-26, 01:48-02:02 PKT, against the running stack at master `45ca0e1` (PRs #22-#24 merged). The stack
was not restarted. Engines: `SAST_ENGINE=ml` (ml-sast v3 on :8001), `DAST_ENGINE=ml` (ml-dast on :8002). Staging
target: Minikube (Docker driver, 8 CPUs shared, 6 GiB memory limit). No AWS resources were used.

Each run was triggered by `scripts/e2e-smoke.js`, which sends the same HMAC-signed push webhook that GitHub sends
and then reads the results from the database. The existing e2e user (id 5) and its projects 24-27 were used; nothing
was created. Raw outputs are in `docs/evidence/pipeline/`, and the step log is in `docs/e2e-run-progress.md`.

## Runs: expected vs actual

| Run | App (project) | Execution | Expected | Actual | Match |
|---|---|---|---|---|---|
| 1 | demo-forms (27), vulnerable | 110 | BLOCKED at SAST (CRITICAL), later stages skipped | `STAGE_FAILED` at SAST in 19 s: 2 CRITICAL, 4 HIGH. CI/CD view: SAST Failed, the other four Skipped | yes |
| 2 | python-clean (26) | 111 | all stages pass, app runs on Minikube | `COMPLETED` in 135 s. Pod Running with the run-111 image, NodePort answers 200 on `/` and `/health` | yes |
| 3 | e2e-node-express (24) | 112 | same as run 2 | `STAGE_FAILED` at SAST in 6 s: 1 CRITICAL, 2 HIGH | **no** (see below) |
| 4 | python-clean (26), `promote_target=eks` | 113 | Promote `SKIPPED` (target unavailable), node visible after DAST | `COMPLETED` in 68 s. `promote_result.status=SKIPPED`, "target unavailable: PROMOTE_KUBE_CONTEXT not set; ...". CI/CD view: 5 stages Passed, then "Promote to EKS" Skipped. Setting reset to `none` | yes |
| 5a | runs 1-4 | 110-113 | SAST and DAST use engine `ml` | `scan_history.scan_engine=ml` (tool `ml-sast-v3-ensemble 3.0.0`, model sha256 `f28cc42b...`). `dast_scans.scan_engine=ml` | yes |
| 5b | python-clean (26), ml-sast unreachable | 114 | stage fails closed | `ERROR` after 2 SAST attempts (60 s retry): "ML SAST service at http://127.0.0.1:8999 is unreachable (ECONNREFUSED) ... the stage does not fall back to another engine". No later stage ran | yes |
| 6a-c | python-clean (26), repeats for timing | 115-117 | pass | all `COMPLETED` (50 s, 40 s, 128 s). 117 needed a Deploy retry (see failures) | yes, with one flaky retry |

**Run 3:** `e2e-node-express` is an intentionally vulnerable fixture. Its README lists SQL injection on `/users`,
reflected XSS on `/search` and hard-coded secrets, and ml-sast found exactly these: SQL injection at `app.js:17`,
XSS at `app.js:26`, hard-coded credential at `app.js:7`. The block is therefore correct, but the run does not show
a Node app passing every stage. No clean Node fixture is among the allowed e2e apps, and no new app was added.

Historical evidence for Node: executions 70, 71 and 73 (2026-11-19, previous SAST/DAST engines) passed every stage
with this fixture. That deployment is still Running in `cloudsentinel-p-24` and answers 200
(`run3-node-minikube-historical.txt`, `run3-node-historical-execution-73.json`). Under the previous engines the same
vulnerable app passed SAST with 1 non-blocking issue. The ML engine blocks it on the real vulnerable lines.

**Run 5b method:** the stack could not be restarted, so a temporary second backend was started on :3200 from the
same master code and database. It used `ML_SAST_URL=http://127.0.0.1:8999`, with nothing listening there. Stale-scan
cleanup (`SAST_ORPHAN_RUN_MINUTES=0`) and provenance recovery were off. It was stopped right after the run.

## Where the image scan runs

The image scan is part of the **Deploy** stage (`backend/services/deployment.js`), in this order:

1. `docker build` on the host
2. `docker image inspect` to get the immutable image ID
3. **Trivy image scan** on the host (`trivy image --scanners vuln --vuln-type os`, any CRITICAL blocks)
4. `minikube image load`
5. client and server-side (Kyverno) dry runs, `kubectl apply`, rollout, then the pod and service checks

An image that fails the scan therefore never reaches the cluster. The clean Python image has 0 CRITICAL, 54 HIGH,
76 MEDIUM and 77 LOW OS-package vulnerabilities, so it passes, because the gate blocks on CRITICAL only.

## Timing

Per-run stage durations in seconds (`docs/evidence/pipeline/performance-per-run.csv`, long format in `timing.csv`).
Deploy is measured from the end of IaC to `deployed_at` and includes the image scan.

| Run | Execution | SAST | Dependency | IaC | Deploy | of which image scan | DAST | Total | Note |
|---|---|---|---|---|---|---|---|---|---|
| 1 demo-forms | 110 | 19.0 | - | - | - | - | - | 19.1 | blocked at SAST |
| 2 python-clean | 111 | 3.8 | 2.4 | 3.2 | 125.4 | 64.3 | 0.1 | 135.0 | Trivy downloaded its vulnerability DB during this scan |
| 3 node | 112 | 6.1 | - | - | - | - | - | 6.1 | blocked at SAST |
| 4 python-clean + promote | 113 | 7.4 | 7.0 | 3.9 | 49.1 | 6.3 | 0.1 | 67.7 | promote SKIPPED (<0.01 s) |
| 5b ml-sast unreachable | 114 | 1.8 (failed) | - | - | - | - | - | 64.4 | 2 attempts, 60 s back-off |
| 6a python-clean | 115 | 9.0 | 5.6 | 4.4 | 30.3 | 4.1 | 0.1 | 49.6 | |
| 6b python-clean | 116 | 4.1 | 2.8 | 2.1 | 30.3 | 3.1 | 0.1 | 39.5 | |
| 6c python-clean | 117 | 5.5 | 3.2 | 2.1 | 117.6 | 3.7 | 0.1 | 128.5 | Deploy attempt 1 failed, 60 s retry |

Clean Python app, 5 completed runs (`performance-clean-python.csv`):

| Stage | Min | Median | Mean | Max |
|---|---|---|---|---|
| SAST | 3.8 | 5.5 | 6.0 | 9.0 |
| Dependency | 2.4 | 3.2 | 4.2 | 7.0 |
| IaC | 2.1 | 3.2 | 3.1 | 4.4 |
| Deploy (incl. image scan) | 30.3 | 49.1 | 70.5 | 125.4 |
| Image scan | 3.1 | 4.1 | 16.3 | 64.3 |
| DAST | 0.1 | 0.1 | 0.1 | 0.1 |
| **Total** | **39.5** | **67.7** | **84.1** | **135.0** |

### Performance summary (for charts)

- **Deploy dominates.** It is 61-93 % of total pipeline time on the clean app. SAST, Dependency and IaC together
  take 9-19 s.
- **Normal runs:** without a DB refresh or a retry, a full pass takes 40-68 s (median 50 s, 3 runs). The two slow
  runs have known causes:
  - run 2: a one-off Trivy DB download (+60 s), confirmed by the DB's `DownloadedAt` 20:51:24 UTC, inside that scan;
  - run 6c: a flaky Deploy check plus the orchestrator's fixed 60 s retry.
- **Blocked runs finish fast:** 6-19 s, because the pipeline stops at the first failing stage.
- **SAST time is mostly clone and model inference:** 4-9 s for one source file, 19 s for demo-forms.
- **DAST time (0.1 s) is not representative:** see the next section.

Suggested charts: a stacked bar per run from `performance-per-run.csv` (stages as segments), and a box or range
chart per stage from `performance-clean-python.csv`.

## SAST findings (ml-sast v3 ensemble)

| Run | Findings | Severity | `models_agree` |
|---|---|---|---|
| 1 demo-forms | 6 | 2 CRITICAL (SQL injection `app.py:50`, `:92`), 4 HIGH (XSS `app.py:73`, `:84`, `:110`, `:119`) | 3 of 3 models (rf, lgbm, codebert_xgb): 6 |
| 3 node | 3 | 1 CRITICAL (SQL injection `app.js:17`), 2 HIGH (XSS `app.js:26`, hard-coded credential `app.js:7`) | 3 of 3 models: 2; rule-based secrets detector: 1 |
| 2, 4, 6a-c python-clean | 0 | - | - |

Across the run, the ML models flagged 8 findings with 3/3 agreement, the secrets rule flagged 1, and no finding was
flagged by only 1 or 2 of the 3 models.

`models_agree` is not stored in its own column: ml-sast returns it in the API, and the backend keeps it inside the
finding message ("flagged by N of 3 models: ..."). These numbers are parsed from `scan_results.message`.

## DAST (ml-dast)

DAST ran only on the clean Python app (5 runs). Each time it saw:
- 1 page and 3 requests;
- 0 forms, 0 injection points found, 0 probed;
- 1 finding: INFORMATIONAL, `X-Content-Type-Options Header Missing` (CWE-693) on `GET /`.

The clean app has only `/` and `/health` (JSON) and no parameters, so DAST had nothing to attack. That is why it
takes 0.1 s.

**Limitation for the report:** the pipeline runs DAST only after SAST passes, so the vulnerable e2e apps (demo-forms,
node, python-flask) never reach DAST. This run therefore does not show DAST detecting anything in the pipeline. The
DAST model's detection results are in its own evaluation (`docs/ml-dast-model-card.md`), not in this run.

## Minikube resource use during Deploy

The cluster has no metrics API (metrics-server is not enabled, and it was not installed to avoid changing the
cluster). `docker stats` on the Minikube container was sampled every 3 s (`run*-minikube-stats.csv`). These numbers
cover the whole cluster, including Kyverno, the monitoring namespace and the other staged apps. CPU % is relative to
one core, with 8 cores available.

| Run | Samples | Memory mean / peak (MiB of 6144) | CPU mean / peak (%) |
|---|---|---|---|
| 2 | 29 | 4471 / 4650 | 57 / 227 |
| 4 | 11 | 4642 / 4709 | 485 / 612 |
| 6a | 7 | 4511 / 4545 | 75 / 185 |
| 6b | 8 | 4578 / 4657 | 68 / 139 |
| 6c | 28 | 4642 / 4727 | 50 / 150 |

- **Memory:** about 4.5-4.7 GiB is in use, and a deploy adds at most about 180 MiB at its peak.
- **CPU:** noisy. Run 4's high CPU was already present before its Deploy started (158 % in the sample just before),
  so it is background cluster load, not the deploy itself.
- **App pod:** requests 100m CPU / 128 Mi, limits 500m / 512 Mi.
- **Node allocation:** 1890m CPU requested (23 %) and 1772 Mi memory requested (8 %).

## Failures, surprises and mistakes

1. **Flaky Deploy check (product bug, not fixed).** Execution 117's Deploy attempt 1 failed with "Running pod does
   not reference expected image ...". `deployment.js:542-548` takes the *first* pod that is `Running` with a ready
   container. During a rolling update, the old pod is still `Running`/ready while it terminates (run 2's kubectl
   output shows exactly such a `Terminating` pod), and pods being deleted are not excluded. The orchestrator's retry
   after 60 s passed, so the pipeline result was right, but the run took 128 s instead of about 45 s. Evidence:
   `run6c-deploy-retry-backend-log.txt`.
2. **Run 3 did not match the expectation:** the Node fixture is intentionally vulnerable, and the block is a true
   positive. A full Node pass was not shown in this run (see above).
3. **The first Trivy scan of the day is slow:** run 2's 64 s image scan included the vulnerability-DB download.
   Expect this once every 24 h.
4. **Loki push failures (configuration):** the backend logged 17 `loki_push_failed` events, because `LOKI_PUSH_URL`
   points at `localhost:3100` and no Loki listens there. Application logs still go to `~/backend.log`.
5. **Promote reason text:** the CI/CD node shows the full configuration reason, including the approved AWS account
   ID, and the page truncates it. Cosmetic, not a security issue: no credentials are shown.
6. **e2e tooling gaps (not product):**
   - `e2e-smoke.js` prints no Deploy duration, because `deployment_history` has no start time; the durations here
     are derived from the IaC end and `deployed_at`.
   - It prints `NOT_RUN` where the UI says "Skipped".
   - The Deploy stage's sub-steps (build, load, rollout) are not timestamped in the log, so they could not be timed
     separately.
7. **My mistakes during the run (none changed any result):**
   - The first attempt of run 4 passed a label instead of an app name to the e2e script, so nothing ran (no
     execution was created).
   - One reset command lost its variables on the way into WSL and did nothing; it was rerun from a script.
   - An awk parser looped and was stopped.

## Known failing backend tests (23)

`cd backend && node --test test/*.test.js` on master: 1004 tests, 973 pass, **23 fail**, 8 skipped. This is the same
set as before the EKS and promote merges. Details: `docs/evidence/pipeline/backend-known-failures-raw.txt`.

**Look like environment/how-run issues. They pass from the repo root** (`node --test backend/test/<file>`: 65/65).
They open files through repo-root-relative paths (`backend/...`), so they fail when the suite runs from `backend/`:
- frontend renders eligibility separately from deployment and escapes reasons
- migration has durable idempotency, ownership and immutable evidence constraints
- orchestrator decision follows completion and cleanup, not webhook acceptance
- security routes pin before scanning and attest before checkout cleanup
- duplicate webhook wakes durable recovery; legacy production worker and AWS consumer unchanged
- recovery schema is additive and does not alter applied migration 017
- scanners replace only the current scan; retention migration protects duplicate writes and completed cascades

**Environment: they need a compiled native CONNECT peer binary** in `/tmp/cloudsentinel-connect-peer-build-*`, which
no longer exists. This is frozen legacy ZAP/DAST gateway code:
- full native CONNECT preserves every probe and fails closed with lifecycle cleanup
- native opt-in diagnostic delivers only the audited client and cleans staged binary
- partial native provisioning failures remove only their staged artifacts
- client removal failure retains mounted native artifact until ownership-verified cleanup succeeds
- audited native artifact stages privately with exact digest and unique ownership
- source and binary hash mismatches reject before staging
- symlinks and directory substitutions cannot be verified or cleaned as owned
- wrong ownership, permissions, architecture and modified bytes are rejected
- owned cleanup removes staged artifacts and disallows stale reuse
- cleanup retries safely after partial deletion without touching foreign directory contents
- native container mount and security settings are constructed and inspected
- experimental same-socket result must match independently inspected gateway and authority
- wrong or missing peer, headers, authority, timeout and contradictory output fail closed
- ownership mismatch prevents experimental executable invocation
- caller retains lifecycle cleanup on experimental verification failure

**Probably time-dependent, legacy ZAP (frozen):**
- diagnostic scope rejects arbitrary images, URLs, operations, Project 17 and expiry. It fails with
  `INVALID_DIAGNOSTIC_SCOPE`, most likely because the diagnostic's expiry date has passed. Not investigated further,
  since the code is frozen.

None of the 23 failures is in the EKS, promote or ML engine code.

## Bugs to fix (reported only, nothing changed)

1. `backend/services/deployment.js:542-548`: the pod check must ignore pods with `metadata.deletionTimestamp` (or
   require that every ready, non-terminating pod runs the new image). Without that it fails intermittently during
   rolling updates, and the 60 s retry hides it.
2. Configuration: `LOKI_PUSH_URL` in the stack's `.env` points at a port with no Loki. Either remove it or point it
   at the Minikube Loki.
3. Tests: run the 7 path-dependent tests from the repo root, or make their paths relative to `__dirname`. The native
   gateway and ZAP diagnostic tests need their build artifact or a skip guard.
4. Test coverage: add a clean Node.js fixture, so the e2e suite can show a Node app passing every stage under the
   ML engines.
