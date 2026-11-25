# End-to-end pipeline run on the local stack: progress log

Worktree `~/cs-e2e-run`, branch `test/e2e-evidence` from origin/master 45ca0e1 (PRs #22-#24 merged). The running
stack (3000/5173/8001/8002) is master 45ca0e1; it was not restarted. Engines: `SAST_ENGINE=ml`, `DAST_ENGINE=ml`.
Staging: Minikube (default context `minikube`, unchanged). No AWS, no EKS.

Test user: the existing e2e user (id 5). Test projects: the existing e2e projects 24 (node), 25 (python-flask),
26 (python-clean), 27 (demo-forms), created 2026-11-19/20. None were created in this run, so cleanup only restores
settings changed here.

| Step | Status | Time (PKT) | Notes |
|---|---|---|---|
| Setup | done | 01:47 | worktree, env flags checked (names only), ML services healthy (/health 200, model trained), Minikube running, metrics API not installed (resource use sampled with `docker stats` on the Minikube container) |
| Run 1 demo-forms | done (as expected) | 01:48 | execution 110 STAGE_FAILED at SAST in 19 s: 6 findings (2 CRITICAL, 4 HIGH), engine ml; no rows for later stages; CI/CD API view: SAST Failed, Dependency/IaC/Deploy/DAST Skipped |
| Run 2 python-clean | done (as expected) | 01:49-01:52 | execution 111 COMPLETED in 135 s; Deploy 125 s of which Trivy image scan 64 s (0 CRITICAL, 54 HIGH: gate blocks CRITICAL only); pod Running with the run-111 image, NodePort 200 on / and /health; DAST only 1 page / 3 requests / 0 injection points (app has no forms or parameters), 1 INFO finding |
| Run 3 node (e2e-node-express) | done, NOT as expected | 01:52 | execution 112 STAGE_FAILED at SAST in 6 s: 1 CRITICAL (SQL injection app.js:17, 3/3 models), 2 HIGH (XSS app.js:26, 3/3 models; hardcoded credential app.js:7, rule). Correct: the fixture is intentionally vulnerable (its README lists exactly these). There is no clean Node fixture among the allowed apps, so a full Node pass was not shown in this run. Historical: executions 70/71/73 (2026-11-19, previous engines) passed all stages; that deployment is still Running in cloudsentinel-p-24 and answers 200 (run3-node-minikube-historical.txt) |
| Run 4 promote | done (as expected) | 01:54-01:56 | project 26 set to promote_target=eks via PUT /api/infrastructure/26/promote-settings (200); execution 113 COMPLETED in 68 s; promote_result SKIPPED 'target unavailable: PROMOTE_KUBE_CONTEXT not set; ...' (no PROMOTE_* env in the stack, so no AWS call); CI/CD API view: 5 stages Passed, then 'Promote to EKS' Skipped; reset to none (200). First attempt of this run was my wrapper error (wrong app name, nothing ran) |
