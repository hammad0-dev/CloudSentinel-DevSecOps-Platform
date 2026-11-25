# Promote to EKS (pipeline stage)

Module 8 (cloud deployment). Code: `backend/services/promoteStage.js`, hook in `backend/services/orchestrator.js`
(Phase 4), settings route in `backend/routes/infrastructure.js`, migration `backend/migrations/024_promote_stage.sql`,
UI `frontend/src/pages/CICDPipeline.jsx` + `frontend/src/utils/pipelineStages.js`.

## Pipeline order

```
commit -> SAST -> Dependency -> IaC -> image build + scan + deploy to Minikube (staging) -> DAST [-> Active DAST]
       -> PROMOTE (new)
```

The existing stages are unchanged. The orchestrator reaches Promote only when it did not stop earlier. The stage
checks this again (fail closed): it runs only if SAST, Dependency, IaC, Deploy and DAST are all in
`stages_completed`, plus Active DAST when `DAST_ACTIVE_ENABLED=true`. If DAST was skipped (no staging URL), Promote
records `NOT_RUN`.

## Design

- **Terraform provisions, Kubernetes deploys.** Infrastructure (ECR repository, IRSA role, secrets, log group,
  optional RDS) goes through the existing gated engine `services/eksWorkloadEngine.js`. Its gates still apply: plan
  allowlist, exact-hash single-use approval, `INFRA_APPLY_ENABLED`, kill switch, account `229032674007` and region
  `ap-south-1`. Pods are rolled out from the generated manifests (`services/eksManifests.js`, target=eks), never by
  Terraform.
- **The promoted image is the staging image.** The stage re-tags the exact image that the Deploy stage built,
  scanned and DAST-tested (`deployResult.localImageId`) as `<project ECR repo>:<commit SHA>`. It never uses `latest`
  and does not rebuild. After the push, the pushed manifest's config digest must equal the local image ID.
- **Tags are never overwritten.** If the tag already holds this exact image, the push is skipped. If it holds a
  different image, the stage fails, unless the deployment already runs that tag and is healthy (`ALREADY_PROMOTED`).
  ECR immutability enforces the same rule on the registry side.
- **Admission.** A server-side dry run goes through the cluster's Kyverno policies before anything changes. The
  generated Namespace (PSA `restricted`) is applied for real first, because a dry run cannot create a namespace.
- **Health check.** `kubectl port-forward deployment/<name>` to a random local port, then `GET PROMOTE_HEALTH_PATH`
  (default `/`). A 2xx/3xx response is healthy. This account has no load balancer.
- **Rollback.** If the rollout or the health check fails, the stage runs `kubectl rollout undo`, waits for that
  rollout, and marks the stage `FAILED`. A first deployment has no previous revision, so the result says so.
- **Credentials.** The registry uses the scoped profile (`PROMOTE_AWS_PROFILE`, default `cloudsentinel-dev`).
  `aws ecr get-login-password` output goes only to `docker login --password-stdin`, with a temporary 0700
  `DOCKER_CONFIG` that is deleted afterwards. kubectl always gets `--context $PROMOTE_KUBE_CONTEXT`. The default
  context is never read or changed.
- **Audit.** Every step is appended to the project's `audit.jsonl` (the same file as the infrastructure engine):
  `promote-start`, `promote-infrastructure-approval-required`, `approve-apply` (with
  `approvedBy: "pipeline gates (execution N)"`), `promote-push`, `promote-apply` (with the previous image),
  `promote-rollout`, `promote-rollback`, `promote-result`. Entries record the commit, tag, result and principal, and
  never secrets. The stage result (status, reason, steps, plan summary) is stored in
  `pipeline_executions.promote_result`.

## Configuration

Per project, in the `projects` table (migration 024). Set them with
`PUT /api/infrastructure/:projectId/promote-settings {promote_target, promote_approval}` (owner only):

| Setting | Values | Default |
|---|---|---|
| `promote_target` | `none`, `eks` | `none` (stage does nothing, nothing recorded, behaviour unchanged) |
| `promote_approval` | `manual`, `auto_after_gates` | `manual` |

Environment only (never from repository text). A missing or wrong value means "target unavailable":

| Variable | Meaning |
|---|---|
| `PROMOTE_KUBE_CONTEXT` | kubectl context of the approved cluster (e.g. `eks-cloudsentinel`) |
| `PROMOTE_REGISTRY` | must be `<account>.dkr.ecr.<region>.amazonaws.com` |
| `PROMOTE_AWS_ACCOUNT` / `PROMOTE_AWS_REGION` | must be `229032674007` / `ap-south-1` (the engine's pins) |
| `PROMOTE_AWS_PROFILE` | registry profile (default `INFRA_AWS_PROFILE`, then `cloudsentinel-dev`) |
| `PROMOTE_ROLLOUT_TIMEOUT_SECONDS` | 30-900, default 180 |
| `PROMOTE_HEALTH_PATH` | default `/` |

Until migration 024 is applied, the settings read as `none`. A database error also reads as `none` (no promotion).

## Decision table

| Situation | Stage status | Pipeline result |
|---|---|---|
| `promote_target=none` | (not recorded) | unchanged |
| An earlier stage failed, was blocked or skipped | `NOT_RUN` | unchanged (earlier result) |
| Target config missing or wrong, or cluster unreachable | `SKIPPED` ("target unavailable: ...") | unchanged (COMPLETED) |
| Infrastructure not applied, `manual` | `APPROVAL_REQUIRED` "infrastructure approval required" + plan summary | COMPLETED |
| Infrastructure not applied, `auto_after_gates`, allowlist pass, apply gate open | approve exact hash (`pipeline gates`), apply, then deploy | per deploy result |
| `auto_after_gates`, allowlist rejects the plan | `NEEDS_REVIEW` (ask a human) | COMPLETED |
| `auto_after_gates`, `INFRA_APPLY_ENABLED` off or kill switch on | `NEEDS_REVIEW` | COMPLETED |
| Architecture or entrypoint needs confirmation; record busy (applying, needs review, destroying) | `NEEDS_REVIEW` | COMPLETED |
| AWS login expired | `NEEDS_REVIEW` ("run aws login --profile ...") | COMPLETED |
| Plan, infrastructure apply, manifest generation, push or admission dry run failed | `FAILED` | STAGE_FAILED |
| Tag exists with a different image | `FAILED` (refused to overwrite) | STAGE_FAILED |
| Rollout or health check failed | `FAILED`, `kubectl rollout undo` | STAGE_FAILED |
| Pushed, rolled out, healthy | `PROMOTED` | COMPLETED |
| Same commit already deployed and healthy | `ALREADY_PROMOTED` | COMPLETED |

`PROMOTED`, `ALREADY_PROMOTED` and `FAILED` add "Promote" to `stages_completed`. The CI/CD view shows a
"Promote to EKS" node whenever `promote_result` exists, with its status, reason, short tag, plan summary and
approver.

Idempotency: a second run with the same commit finds the tag holding the same image (push skipped, re-apply is a
no-op) or finds the commit already deployed (`ALREADY_PROMOTED`). A plan awaiting manual approval for the same
repository state is reused, not re-planned.

## Tests

- `backend/test/promote-stage.test.js` (unit, 16 tests): all passed; earlier stage failed; `none`; manual approval;
  auto + allowlist pass; auto + allowlist reject; gate closed; apply failure; unreachable; config wrong; push
  conflict; immutable race; expired login; rerun idempotency; rollout failure + undo; health failure + undo; first
  deploy without a revision; admission denial; ECR password handling; explicit `--context`; result recording.
- `backend/test/promote-minikube.integration.test.js` (`PROMOTE_IT=1`): Minikube as the stand-in target, with the
  real generated Dockerfile and manifests, the real kube adapter and Kyverno. Runs: promote, idempotent rerun,
  broken image (rollout timeout, undo, previous image healthy), tag conflict refused. Evidence:
  `docs/evidence/eks/promote/01-minikube-integration.txt`.
- `frontend/src/utils/pipelineStages.test.js`: stage list and Promote node labels.

## Limitations

- **One approved cluster.** One kube context, one account and one region, all from the environment.
- **One component per promotion.** The staging stage builds one image, so two- and three-tier projects stop at
  `NEEDS_REVIEW`. Promoting them needs one scanned image per component.
- **Health check via port-forward only.** This account (AWS Free plan) cannot create load balancers. The generated
  public `LoadBalancer` Service stays Pending. The 9101 NLB from Stage 5 was a one-off created by controller
  retries.
- **First-time Terraform path tested only.** The analyze/plan/approval/apply path (including `auto_after_gates`) is
  covered by unit tests with a stand-in engine, not by a live apply.
- **EKS check on project 9101 only, and only the "target unavailable" outcome.** See
  `docs/evidence/eks/promote/02-live-9101-target-unavailable.txt`:
  - On 2026-11-25 the EKS API endpoint was unreachable because the workstation's public IP had changed and the
    cluster allows only the old /32. The stage correctly returned `SKIPPED`, pushed nothing and appended audit
    entries.
  - The live push and rollout path was not run. Two reasons: it would need an AWS change (the endpoint CIDR), and
    the 9101 image fails the pipeline's own image gate (CRITICAL `zlib` CVE-2023-45853, `will_not_fix`, in the
    pinned Python base image), so the stage must not promote it.
- `scripts/promote-verify.js` is an operator check, not a pipeline run. The operator asserts the earlier stages,
  and the script enforces the image gate itself.
- Migration 024 is not applied to the shared database yet. Until it is, every project reads `promote_target=none`.
