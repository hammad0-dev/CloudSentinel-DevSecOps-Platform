# EKS rollout progress log (Modules 8-11)

Running log for the EKS task (branch `feat/iac-generator`, worktree `~/cs-iac`). It is written so the work can be
resumed after an interruption. Times are PKT (UTC+5).

**Mode: UNATTENDED (2026-11-23).** Only Stages 1-3 (up to and including `terraform plan`). No apply, no AWS resource
created or changed, no push, no PR, no `docs/eks-deployment.md`, no `docs/traceability.md` change.

**Billable AWS resources created by this work: NONE.** (Only read-only `describe-*`/`list-*` calls and `terraform plan`.)

## Status

| Stage | Status | Started | Finished | Billable |
|---|---|---|---|---|
| Setup (worktree, baseline tests) | done | 13:05 | 13:12 | no |
| 1 Generator and templates | done | 13:12 | 14:00 | no |
| 2 Minikube tests | done | 14:17 | 14:47 | no |
| 3 Shared infrastructure code, plan, cost gate | done, **waiting at STOP 1** | 14:50 | 15:10 | no (plan only) |
| 4-8 | NOT RUN (unattended mode) | | | |

## Setup

- Worktree `~/cs-iac` on `feat/iac-generator` from `origin/master` (389bea4), upstream unset.
- `node_modules` and `frontend/node_modules` are untracked symlinks to `~/CloudSentinel` (read only, as in `~/cs-engines`).
- Disk at start: C: 31 GB free, D: 114 GB free (limits 15 / 60 GB).
- Baseline backend tests (`cd backend && node --test test/*.test.js`): 961 tests, **935 pass, 23 fail, 3 skipped**
  (the known 23 failures, not ours).
- Tools: terraform 1.16.6, helm 3.22.1, trivy 0.52.2, aws-cli 2.38.1, kubectl, minikube; node 18.20.8.
  Not installed: kyverno CLI, jq.

## Read-only AWS findings (13:15)

- `cloudsentinel-admin`: credentials valid, account 229032674007.
- `cloudsentinel-dev`: **blocked** - the CLI fails with `AWS_ERROR_CAL_UNSUPPORTED_KEY_FORMAT: Key format is not
  supported` before any API call. Needed only from Stage 5 on. The user must re-run `aws login --profile cloudsentinel-dev`
  (or re-create that profile's credentials). `~/.aws` was not read.
- EKS versions in ap-south-1 (`aws eks describe-cluster-versions`): 1.37 (default), 1.36, 1.35, 1.34 are STANDARD
  support; 1.30-1.33 are EXTENDED (paid). 1.34 standard support ends 2026-12-02.
- Free-plan-eligible instance types (`describe-instance-types --filters Name=free-tier-eligible,Values=true`):
  t3.micro, t3.small, t4g.micro, t4g.small, t8i.micro, t8i.small, c7i-flex.large (4 GiB), m7i-flex.large (8 GiB).
  m7i-flex.large is offered in ap-south-1a/b/c.
- RDS: `db.t4g.micro` is not orderable in ap-south-1 for postgres or mysql; `db.t3.micro` is.
- **GuardDuty: blocked by the Free plan.** `aws guardduty list-detectors` returns `SubscriptionRequiredException: The AWS
  Access Key Id needs a subscription for the service`. Per the brief, not worked around: GuardDuty is behind a variable
  that defaults to off, and is listed at the cost gate as needing a Paid plan.
- Existing VPCs: default 172.31.0.0/16 and `cloudsentinel-p13-development-vpc` 10.0.0.0/16 (protected project 13).
  No EKS cluster, no CloudTrail trail.

## Stage 1 - generator and templates (done 14:00, nothing billable)

| Item | Result |
|---|---|
| Templates | `terraform/templates/eks-project` (root), `terraform/modules/project-workload`, `terraform/modules/project-database`; aws provider = 6.70.0, lock file committed |
| Generator | `backend/services/eksWorkload.js` (detect, classify, tfvars, Dockerfile, plan + destroy allowlist), `eksManifests.js`, `deployment.js` target=eks mode |
| Lifecycle / gates | `backend/services/eksWorkloadEngine.js`; routes `/api/infrastructure/:id/workload/*`; `/apply` gated; CLI `scripts/infra-cli.js`; minimal UI `WorkloadInfrastructure.jsx` |
| IAM for cloudsentinel-dev | `terraform/docs/policies/cloudsentinel-dev-container.json` + `cloudsentinel-dev-container-guardrails.json` |
| Unit tests | `npm run test:eks`: 20/20 pass |
| Terraform + Trivy | `npm run test:eks:terraform`: 4/4 pass (one-tier, two-tier PostgreSQL, two-tier MySQL, three-tier): fmt, init -backend=false, validate; Trivy: 0 CRITICAL, 0 HIGH |
| Backend suite | before 961 tests / 935 pass / 23 fail / 3 skip; after 984 / 954 / 24 / 6. The extra failure is `monitoring routes: scoped logs, context, SSE` (a 1 ms timing assertion, 660001 vs 660000), not touched by this work; it passed 5/5 re-runs. The 23 known failures are unchanged (same names). |
| Evidence | `docs/evidence/eks/stage1/` (unit-tests.txt, terraform-trivy.txt, infra-cli-smoke.txt) |

Trivy findings kept (LOW/MEDIUM, demo trade-offs, listed in `terraform-trivy.txt`): AWS-managed keys instead of a CMK
for log groups, ECR and secrets (AVD-AWS-0017/0033/0098, LOW); RDS 1-day backups, no deletion protection, no
Performance Insights (AVD-AWS-0077/0177 MEDIUM, 0133 LOW: the demo is destroyed at the end); no Docker HEALTHCHECK
(DS026, LOW: Kubernetes readiness probes are used); `DB_PORT` in a ConfigMap flagged as "sensitive" (KSV-01010
MEDIUM, false positive: it is a port number; the key `PORT` was removed from the ConfigMap for the same reason).

Surprises and fixes during Stage 1:
- The AWS provider failed with "Unrecognized remote plugin message" when TMPDIR was on /mnt/d: providers bind a unix
  socket in TMPDIR and the 9p mount cannot hold sockets. Fix: TMPDIR stays default for terraform (socket only); the
  plugin cache stays on D: (`TF_PLUGIN_CACHE_DIR=/mnt/d/cs-data/tf-plugin-cache`).
- Trivy is a snap with a private /tmp, so it cannot scan /tmp. The real-tool test uses `/mnt/d/cs-data/tmp`.
- **Trivy silently checked nothing** in the generated root (1 check) because it cannot expand `for_each`/`count`
  modules without variables. Fix: `--tf-vars terraform.tfvars.json` (7-22 checks per folder) and the engine now refuses
  a plan if the scan did not evaluate the workload module.
- Port detection took `DB_PORT || 5432` as the listen port; fixed (word boundary).
- Writing the dev IAM policy showed a privilege-escalation path (a principal that can CreateRole + PutRolePolicy can
  make itself an admin role). Fix: every IRSA role must carry the permissions boundary
  `cloudsentinel-workload-boundary` (created by the shared environment); the dev policy allows CreateRole/PutRolePolicy
  only with that boundary, denies removing it, AttachRolePolicy, UpdateAssumeRolePolicy and PassRole; the plan
  allowlist checks the boundary. Residual risk: dev can still create a boundary-limited role trusted by any principal,
  so its worst case is reading `cloudsentinel/*` secrets (documented).
- One dev policy was 6,957 characters (limit 6,144) and is split into two managed policies.

What to attach and when (user, IAM console, before Stage 5, after Stage 4 has created the boundary policy):
IAM -> Users -> cloudsentinel-dev -> Add permissions -> Create policy (JSON) twice, from
`terraform/docs/policies/cloudsentinel-dev-container.json` (name `cloudsentinel-dev-container`) and
`terraform/docs/policies/cloudsentinel-dev-container-guardrails.json` (name `cloudsentinel-dev-container-guardrails`),
then attach both to the user. Fix the cloudsentinel-dev credentials first (see Blocked).

## Stage 2 - Minikube tests (done 14:47, nothing billable)

| Item | Result |
|---|---|
| Kyverno CLI 1.19.2 | generated manifests (app, frontend, backend) pass 27/27 rules; 6 violating pods fail on the intended rule |
| Kyverno admission (Enforce, 7 policies scoped to `cloudsentinel-p-9001`) | generated app admitted and running; root, latest, no-limits, privileged, untrusted-registry, privilege-escalation pods denied; policy reports 16 pass / 0 fail |
| ESO 2.14.0, fake provider | app secret and RDS-style DB secret synced; pod gets them as env vars and mounted files |
| Rotation | mounted file changed 30 s after the new value, env unchanged, no redeploy; `scripts/rotate-secret.sh` dry run only (no AWS in this stage) |
| RBAC | deployer: deployments/services/configmaps/HPA, logs, no Secrets, no exec, no ExternalSecret creation; viewer: read only, no Secrets, no logs; neither reaches other namespaces |
| HPA | 2 -> 4 replicas after about 66 s of load (CPU 129% of the 70% target) |
| Cleanup | test namespaces, `eks-test-*` policies, ESO and CRDs, metrics-server, test image removed; existing pods unchanged |
| Evidence | `docs/evidence/eks/minikube/` (README lists the files and the mistakes made during the run) |

Measured memory (working set): Kyverno 4 pods about 290 Mi; ESO 3 pods about 110 Mi; existing monitoring stack
(kube-prometheus-stack + Loki + Promtail) about 940 Mi (Prometheus 401 Mi, Grafana 173 Mi, Loki 153 Mi); app pod
about 29 Mi each (126-133 m CPU under load). Node-level: 4.6-4.8 GiB of 20 GiB in use with the rest of Minikube.

Sizing for EKS (decision: 2 x m7i-flex.large, 8 GiB / 2 vCPU each, min 2 / max 3): add-ons and platform about
1.4 GiB (Kyverno, ESO, monitoring) plus EKS system pods (aws-node, kube-proxy, CoreDNS x2, metrics-server, about
0.4 GiB per node) plus up to 8 app pods; memory fits on one node, but the VPC CNI limit of 29 pods per
m7i-flex.large and keeping 2 replicas on separate nodes need 2 nodes. c7i-flex.large (4 GiB) would be tight with
Prometheus; t3.small (2 GiB, 11 pods) is too small.

Surprises: Minikube already had Kyverno 1.19.2 and the monitoring stack (kps, loki, promtail) installed, so they
were measured, not reinstalled. The existing Grafana pod is crash-looping (685 restarts; not touched). The repo's
`k8s/monitoring/README.md` says Grafana is disabled, but it is installed. Pod Security "restricted" answers before
Kyverno for privileged/root pods, so the Kyverno-only test labelled the namespace `enforce=privileged` for the
duration of that step.

## Stage 3 - shared environment and cost gate (done 15:10, nothing billable)

| Item | Result |
|---|---|
| Code | `terraform/environments/aws-demo/{main,security,variables,outputs}.tf`, `aws-demo.tfvars`, `.terraform.lock.hcl` (aws 6.70.0, tls, time, null pinned by the lock); modules vpc 6.7.2, eks 21.29.0 |
| Checks | `terraform fmt -check`, `init`, `validate`: pass |
| Plan | profile cloudsentinel-admin, 35 s: **82 to add, 0 change, 0 destroy**; all create; all taggable resources tagged. Saved as `terraform/environments/aws-demo/shared.tfplan` (gitignored; copy in `/mnt/d/cs-data/eks-work/`), sha256 `09485a7bc11cb289e3311394ba86066d66d72a42b56014952dd5a717ab78a44d`. **Not appliable: alert_email placeholder** |
| Trivy | 308 checks, 0 CRITICAL, 3 HIGH: 2 in example YAML shipped inside the downloaded EKS module (not deployed), 1 AVD-AWS-0057 on the KMS key policy (`Resource: "*"` is how key policies refer to their own key) |
| Cost gate | `docs/eks-cost-gate.md`: about $0.66/hour with the Stage 5 apps, $0.53/hour shared only, about $3.30 per 5 hours (upper estimate $4.30) |

Decisions:
- decision: Kubernetes 1.36 because it is in standard support until 2027-08-02 and is not the newest release (1.37),
  giving add-ons and charts (Kyverno 1.19, ESO 2.14, kube-prometheus-stack) more time to support it.
- decision: EKS API endpoint public but limited to the current public IP /32 (gitignored `local.tfvars`) plus private
  access, because 0.0.0.0/0 is a CRITICAL finding and the backend/kubectl run from this machine. If the IP changes,
  update `local.tfvars` and re-plan.
- decision: CloudTrail is multi-region with global service events because the first copy of management events is
  free and IAM/STS denials (the alarm's main signal) are global events.
- decision: one customer-managed KMS key for CloudTrail, its log group and the SNS topic, because CloudWatch alarms
  and EventBridge cannot publish to an SNS topic encrypted with the AWS-managed `aws/sns` key.
- decision: no EBS CSI add-on because no component in the demo uses a PersistentVolumeClaim.
- decision: the old `terraform/modules/eks-cluster` (unpinned, us-east-1, 1.30) is left untouched and unused; the
  environment now calls the pinned registry modules directly.
- decision: the plan used a placeholder alert email instead of stopping, because a plan is free and shows every
  other resource; it is recorded as not appliable and Stage 4 must re-plan.

## Stage 4 pre-checks after "go" (2026-11-25 16:20-17:00 PKT, nothing billable)

| Item | Result |
|---|---|
| Alert email | `TF_VAR_alert_email` **not visible** to my shells (not in the WSL login shell, profile files, or Windows env); an `export` in your own terminal does not reach them. Stage 4 apply not started |
| cloudsentinel-dev | still `AWS_ERROR_CAL_UNSUPPORTED_KEY_FORMAT` |
| Public IP | changed since Stage 3; `local.tfvars` refreshed |
| Cost gate | updated for 2 RDS (both PostgreSQL) + 3 NLBs + 7 IPv4: about $0.73/hour, $3.70 per 5 hours (upper $4.70) |
| GuardDuty EventBridge | rule, target and `events.amazonaws.com` grants removed |
| Versions | add-ons pinned; Kyverno 1.20.0 (1.19 not supported on 1.36); kps 93.1.2, Loki 7.5.0, Alloy 1.14.4, Falco 9.2.2; `k8s/eks/versions.env` |
| Kyverno CEL port | `k8s/kyverno/eks-cel/` (7 ValidatingPolicy); CLI 1.20.0 (checksum-verified): generated 21/21 pass, every violation fails on its rule, other namespace skipped 7/7 |
| Verification plan | placeholder email, saved as `check-placeholder.tfplan` (never apply): 82 creates, all tagged, sha256 `76b49e65...321e2` |

Decisions:
- decision: Kyverno 1.20.0 / chart 3.10.0 on EKS because 1.19 supports Kubernetes 1.33-1.35 only and the user said
  not to lower the cluster version; it is 13 days old (one day under the two-week rule) because no older release
  supports 1.36.
- decision: port the seven policies to CEL ValidatingPolicy in a new folder `k8s/kyverno/eks-cel/` because Kyverno 1.20
  refuses ClusterPolicy; Minikube keeps 1.19.2 and the ClusterPolicy files unchanged.
- decision: EKS add-ons pinned to the AWS default build for 1.36 because `{}` installs the latest build.
- decision: Loki + Grafana Alloy instead of Promtail because the Promtail chart is marked deprecated.
- decision: keep the GuardDuty detector code behind `enable_guardduty=false` but remove the EventBridge rule and the
  events grants, as the user asked.
- decision: when `TF_VAR_alert_email` is missing, the plan script reads `~/.config/cloudsentinel/alert-email`
  (mode 600, outside the repo, never printed); with neither, it saves `check-placeholder.tfplan`, never `shared.tfplan`.

Mistake: a `mkdir` on a UNC path failed and the seven new policy files were written into the root of
`~/CloudSentinel` for about one minute. They were untracked new files (nothing overwritten, never in its history)
and were moved to `~/cs-iac/k8s/kyverno/eks-cel/`. `~/CloudSentinel` also has an untracked
`terraform/environments/aws-demo/.terraform.lock.hcl` dated 2026-11-22 16:06, older than this session; left as is.

## Stage 4 - shared cluster (BILLABLE from the apply start)

- Plan with the real alert address: 82 to add, all create, all tagged; sha256
  `b705182b3472c823bc1c9f23a7d64ea18c7977a4da4dcf9b552a378b08bd3d63`. Both dev policies attached to cloudsentinel-dev.
- **BILLABLE since 2026-11-25 17:46:48 PKT** (apply start; end 17:59:12, 82 added, 12.4 min). State backed up to
  `/mnt/d/ml-backup/eks-state/shared/`. Cluster ACTIVE, Kubernetes 1.36 (eks.19), 2 nodes Ready (kubelet
  v1.36.5), system pods Running, add-ons on the pinned builds, SNS email subscription confirmed (has an ARN).
  ESO 2.14.0 + ClusterSecretStore `cloudsentinel-aws` (Valid), Kyverno 1.20.0 + 7 CEL policies (READY).
  Evidence: `docs/evidence/eks/stage4/{cluster-check,platform-install}.txt`. kube context `eks-cloudsentinel`
  (current context left on minikube).
- Before destroy: delete LoadBalancer Services, helm uninstall, delete policies before Kyverno (Stage 7). Destroy command (after Stage 7 step 1-2 cleanup):
  `cd ~/cs-iac/terraform/environments/aws-demo && AWS_PROFILE=cloudsentinel-admin TF_VAR_alert_email=$(cat ~/.config/cloudsentinel/alert-email) terraform destroy -var-file=aws-demo.tfvars -var-file=local.tfvars`

## Stage 5 - projects (STOPPED 2026-11-25 18:32 PKT: Free plan refuses load balancers)

| Project | Fixture | Result |
|---|---|---|
| 9101 one-tier | cloudsentinel-test-python-clean | analyze, confirm, plan (allowlist OK), approve (single use; reuse refused), apply: 5 resources. Image built from the generated Dockerfile, pushed with cloudsentinel-dev, ECR rejected a tag overwrite (immutable). Deployed: Kyverno admitted it, 2 pods Running on both nodes. **Public Service stuck: `OperationNotPermitted: This AWS account currently does not support creating load balancers.`** |
| 9102 two-tier | cloudsentinel-test-flask-postgres | plan OK (8 resources); apply **failed at RDS**: `KMSKeyNotAccessibleFault` (cloudsentinel-dev may not use the aws/rds key). 7 of 8 resources exist (no DB instance) |
| 9103 three-tier | cloudsentinel-test-three-tier | same RDS failure; 12 of 13 resources exist (no DB instance) |
| 9104 static | cloudsentinel-test-static-site | not applied (as specified). Direct plan of the static module failed: `No valid credential sources found` (the module pins aws provider 5.100.0, which cannot read `aws login` credentials; the EKS templates use 6.70.0) |

Evidence: `docs/evidence/eks/stage5/` (per step JSON, `9101-one-tier-07-deploy.txt`, `stop-load-balancer.txt`).
Gate evidence: `gate-off.json` (blocked without `INFRA_APPLY_ENABLED`), `gate-on.json`.

Fixes during Stage 5:
- Project template: OIDC provider looked up by ARN (`iam:GetOpenIDConnectProvider`, allowed) instead of by URL,
  which needs `iam:ListOpenIDConnectProviders` (not in the scoped dev policy). All three plans failed safely first.
- Engine: a failed apply said "nothing applied" although 7 resources existed; the message now says resources may
  have changed (state is saved either way).
- Dev policy (repo copy only): two KMS statements limited by `kms:ViaService` (RDS, Secrets Manager) and
  `kms:GrantIsForAWSResource`. Changing the live IAM policy was refused by the tool permission check: the user must
  publish it.

decision: stop at the load-balancer refusal because the brief says to stop when AWS answers that the plan does not
allow something; no workaround (NodePort, port-forward as "public" access, other LB types) was tried.

## Decisions

- decision: pin AWS provider 6.70.0, terraform-aws-modules/eks 21.29.0, terraform-aws-modules/vpc 6.7.2 because they
  are the newest releases at least two weeks old (published 2026-10-22, 2026-10-07, 2026-08-28) and eks 21.x needs
  aws >= 6.59. The existing static-site and aws-network modules keep their own 5.100.0 pin (unchanged).
- decision: Kyverno 1.19.2 (the version already running in Minikube) and External Secrets Operator 2.14.0 (2026-10-23)
  because both are over two weeks old and 1.19.2 avoids changing the running Minikube Kyverno.
- decision: RDS class `db.t3.micro` because `db.t4g.micro` is not orderable in ap-south-1.
- decision: shared EKS VPC CIDR 10.40.0.0/16 because 10.0.0.0/16 is used by project 13's VPC.
- decision: GuardDuty resources are behind `enable_guardduty` (default false) because the account answers
  SubscriptionRequiredException (Free plan); the user decides at STOP 1.
- decision: TF_PLUGIN_CACHE_DIR, HELM_*_HOME, Trivy cache and downloaded tools live under `/mnt/d/cs-data/` because
  nothing may be cached on C:.
- decision: PostgreSQL 17.11 and MySQL 8.4.13 because both are orderable on db.t3.micro/gp2 in ap-south-1 and are
  mature majors (18.x and 9.x are newer).
- decision: base images `python:3.12.15-slim-bookworm` and `node:22.23.3-alpine` (pinned tags; 22.23.3 published
  2026-09-23) for generated Dockerfiles; UID 10001.
- decision: per-project state is a local file in the private artifact directory (no S3 backend) because no approved
  state bucket exists for this run; it is backed up to /mnt/d/ml-backup/eks-state/ after every apply/destroy.
- decision: frontend + backend without a detected PostgreSQL/MySQL, or a frontend-only manifest with a database,
  returns MANUAL_REVIEW because the brief says two/three-tier get RDS chosen from the detected database; not guessed.
- decision: the app (one/two-tier) and the three-tier frontend get a `LoadBalancer` Service (NLB annotation); the
  three-tier backend gets `ClusterIP`; the database is private.
- decision: ESO reads app secrets through a ClusterSecretStore `cloudsentinel-aws` (shared IRSA role, as in the brief);
  each project still gets its own IRSA role limited to its own secret and log group for direct SDK use.
- decision: DB_USER/DB_PASSWORD come from the RDS-managed master secret (`rds!db-*`) via ESO; DB_HOST/PORT/NAME from a
  ConfigMap rendered from Terraform outputs; `DATABASE_URL` is built by an ESO template only if the app reads it.
- decision: the two new Kyverno policies (trusted registry, disallow privilege escalation) live in `k8s/kyverno/eks/`,
  not in `k8s/kyverno/policies/`, because the trusted-registry policy would block every Minikube image if someone
  applied the whole folder to Minikube.
- decision: plans expire after 30 minutes and approvals after 15 minutes (whichever is first) because terraform plan
  files go stale and the static engine uses the same short windows.

## Blocked

- `cloudsentinel-dev` credentials (see above) - needed from Stage 5.
- GuardDuty (Free plan) - needs a Paid plan; excluded.
- `TF_VAR_alert_email` is not visible to the shells I start (checked again 2026-11-25) - needed for the Stage 4 plan.

## Option 2 (user, 2026-11-25 ~18:40): no public load balancers, port-forward demos, RDS for 9102/9103

| Time (PKT) | Event |
|---|---|
| 18:44 | dev policy v2 (KMS via RDS/Secrets Manager) published by the user; live == repo |
| 18:45 | engine gap: NEEDS_OPERATOR_REVIEW had no way out; added a scoped recovery destroy (state must be a subset of the approved plan; `recoveryAddresses`, unit test) |
| 18:48-18:53 | 9102 recovery destroy (7 resources), fresh plan (8 creates), apply started |
| 18:59 | 9102 apply failed: the engine's **exported** `aws login` credentials (about 15 min lifetime) expired while Terraform waited for RDS. Engine fixed: child processes now get `AWS_PROFILE` (refreshable); regression test added |
| 19:02-19:05 | 9103 recovery destroy (12), fresh plan (13), apply started; 9102 destroy-plan refused: `rds:DescribeDBInstances` on `db:*` |
| 19:13 | 9103 apply failed the same way: the AWS provider reads a DB instance by resource-id filter, which IAM authorizes on `db:*`. **Both RDS instances exist** (available, private, encrypted), both projects NEEDS_OPERATOR_REVIEW |

Needed: dev policy v3 (`DescribeDbInstancesReadOnly`: `rds:DescribeDBInstances` on `db:*`, read-only) - in the repo, must be
published by the user. Then for 9102 and 9103: recovery destroy (scoped) -> analyze -> confirm -> plan -> approve -> apply
(`scratchpad s5_recover.sh` steps; the same CLI commands as Stage 5).

Stage 6 done so far (no RDS needed): RBAC table, Kyverno admission + policy reports, monitoring stack, planted key
(SAST + Trivy), saved Logs Insights queries (Terraform), alarm + SNS history, HPA 2 -> 4. Shared fix applied:
CloudTrail role lacked KMS on its encrypted log group (denied every ~5 min, which kept tripping the alarm).

## Stages 5-6 completed (2026-11-25 19:40-20:30 PKT)

| Item | Result | Evidence |
|---|---|---|
| dev policy v3 | published by the user, live == repo | - |
| 9102 / 9103 | recovery destroy, fresh plan, approval, apply: APPLIED 19:51 / 20:03; RDS PostgreSQL 17.11 db.t3.micro, private, encrypted | stage5/9102-*, 9103-* |
| rotate-secret.sh | real run failed (AWS CLI v2 cannot read `--cli-input-json` from a pipe); fixed: private 0600 file in `$XDG_RUNTIME_DIR`, removed on exit | stage5/9102-two-tier-17-deploy.txt |
| two-tier demo | port-forward: `/`, `/health`, `/db` 200; `/db` connects to RDS as `csadmin` with credentials from the RDS-managed secret via ESO | stage5/9102-two-tier-18-demo.txt |
| Module 9 | manifest has references only; env + mounted file; rotation: file changed after 100 s (ESO 1 m + kubelet sync), env unchanged, generation 1 -> 1, 0 restarts | stage6/12-secrets-runtime-and-rotation.txt |
| three-tier | frontend `/api/items` -> backend -> RDS rows; backend ClusterIP, nodes have no public IP, direct TCP fails; RDS not public, private IP, SG only from node SG on 5432, direct TCP fails. Limitation: no NetworkPolicy inside the cluster | stage5/9103-three-tier-18-demo.txt |
| static 9104 | plan only (exported short-lived credentials for the 5.100.0 provider, module unchanged): 7 creates, static allowlist ACCEPTED, negative test REJECTED; not applied | stage5/9104-static-plan-allowlist.txt |
| logs/metrics | Loki (Alloy) has project, Kyverno, ESO logs; Prometheus node/pod/HPA metrics; all targets up | stage6/09-logs-and-metrics.txt |
| Falco 9.2.2 | modern eBPF; `kubectl exec -it` -> "A shell was spawned in a container with an attached terminal" (first non-TTY attempt did not match the rule); 66 Mi per node | stage6/10-falco.txt |
| incident | walkthrough of the real 14:13 UTC denial across CloudTrail, metric, alarm, SNS, engine audit, EKS audit, flow logs | stage6/11-incident-walkthrough.md |
| capacity | 17-18 pods per node (limit 29), memory 1.1 / 1.7 GiB of 7 GiB per node; Grafana 401 without login and with the chart default password | stage6/13-capacity-and-access.txt |
| **surprise** | **one internet-facing NLB was created for 9101 at 15:06 UTC** by the service controller's retries; 9102/9103 still refused (OperationNotPermitted). Public curl `/health` 200 | stage5/9101-one-tier-09-nlb-surprise.txt |

## Resume here (2026-11-25 20:30 PKT) - STOP 2. BILLABLE: shared cluster since 17:46:48 PKT (about $0.53/hour) + 2 RDS (about $0.06/hour) + 1 NLB since 15:06 UTC (about $0.04/hour with IPs)

Waiting for "destroy". Stage 7 order: (1) delete the LoadBalancer Services (9101 has a real NLB; wait until
`aws elbv2 describe-load-balancers` is empty), (2) delete namespaces cloudsentinel-p-9101..9103, (3) per-project destroy
9103, 9102, 9101 through the engine (destroy-plan, approve --kind destroy, destroy), (4) helm uninstall falco, alloy,
kps, loki, external-secrets; delete the 7 ValidatingPolicies, then helm uninstall kyverno; delete CRDs left by charts,
(5) shared terraform destroy (command in the Stage 4 section), (6) leftover check.

Previous resume notes:

Stopped in Stage 5: the Free plan refuses load balancers. Waiting for the user's decision:
- upgrade to a Paid plan, then: publish dev policy v2 (below), re-plan 9102/9103 (the engine re-plans from the
  saved partial state), approve, apply; the 9101 Service gets its NLB on its own (Kubernetes keeps retrying); or
- accept no public endpoint (user decision; demonstrate apps with `kubectl port-forward`), or
- destroy now (Stage 7): delete namespaces cloudsentinel-p-9101 first, per-project destroy 9101-9103
  (`node scripts/infra-cli.js destroy-plan|approve --kind destroy|destroy --dir <fixture> --project-id <n>` with
  INFRA_APPLY_ENABLED=true and the env in Stage 5), helm uninstall external-secrets and kyverno (delete the 7
  ValidatingPolicies first), then the shared destroy command in the Stage 4 section.
Dev policy v2 for RDS: `terraform/docs/policies/cloudsentinel-dev-container.json` (repo has it; AWS still has v1).

Previous resume notes (Stages 1-3):

Stages 1-3 and the Stage 4 pre-checks are committed on `feat/iac-generator` (not pushed). "go" was given on
2026-11-25; **Stage 4 apply is waiting for the alert email to be readable** (see Blocked). Billable resources: none.

Exact next step (Stage 4):
1. User: put the address in `~/.config/cloudsentinel/alert-email` (`mkdir -p ~/.config/cloudsentinel && chmod 700
   ~/.config/cloudsentinel`, then write the file and `chmod 600` it; never in chat or the repo), or export
   `TF_VAR_alert_email` in `~/.bashrc`.
2. `bash ~/cs-iac/scripts/eks-shared-plan.sh` (refreshes `local.tfvars`, reads the address, writes `shared.tfplan`).
3. Confirm 82 creates, record the plan sha256, write the start time here, then `terraform apply shared.tfplan`.
4. Back up state: `mkdir -p /mnt/d/ml-backup/eks-state/shared && cp terraform.tfstate /mnt/d/ml-backup/eks-state/shared/terraform.tfstate.$(date +%F-%H%M)`.
5. `aws eks update-kubeconfig --region ap-south-1 --name cloudsentinel-eks --profile cloudsentinel-admin`, `kubectl get nodes`, `kubectl get pods -A`.
6. Remind the user to click the SNS confirmation email. Destroy command (once anything exists):
   `cd ~/cs-iac/terraform/environments/aws-demo && terraform destroy -var-file=aws-demo.tfvars -var-file=local.tfvars`
   (first delete LoadBalancer Services, PVCs, Helm releases and Kyverno policies; Stage 7).
Before Stage 5: fix the cloudsentinel-dev credentials and attach the two dev policies (Stage 1 section).
