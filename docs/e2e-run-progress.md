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
