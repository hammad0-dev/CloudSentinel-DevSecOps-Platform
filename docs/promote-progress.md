# Promote to EKS stage: progress log

Branch `feat/promote-stage` in worktree `~/cs-promote`, created from local `feat/iac-generator` (a85c189), **not** from
origin/master: the promote stage needs the EKS workload engine, manifests and allowlist that exist only on
`feat/iac-generator`, which is not merged (and not pushed) yet. Requirement: Module 8 (FE-8.x deployment to the cloud
target); traceability to be recorded in Stage 8 with the rest of the EKS work.

Hard stop 00:30 PKT. The EKS cluster (`eks-cloudsentinel`) is billing; destroy is done from the other session.

| Step | Status | Time (PKT) | Notes |
|---|---|---|---|
| Worktree + baseline tests | done | 22:12-22:20 | `cd backend && node --test test/*.test.js`: 987 tests, 957 pass, **23 fail**, 7 skipped (all pre-existing: commissioning/native/migration tests). The brief said 24; this tree has 23. |
| Stage module + orchestrator hook + migration + settings route | done | 22:20-22:35 | `services/promoteStage.js`, `orchestrator.js` Phase 4, `migrations/024_promote_stage.sql` (NOT applied to the shared DB), `PUT/GET /api/infrastructure/:id/promote-settings` |
| Unit tests | done | 22:35 | `test/promote-stage.test.js` 16/16; `test/eks-workload.test.js` still 22/22 |
| Minikube integration test | done | 22:23-22:29 | First run FAILED: a server-side dry run cannot create the namespace ("namespaces ... not found"). That would have broken every first promotion. Fixed (apply the generated Namespace first), second run passed: promote, rerun, broken image rolled back, tag conflict refused. Throw-away namespace deleted. |
| Frontend stage view | done | 22:28 | "Promote to EKS" node; `pipelineStages.test.js` 2/2; `vite build` OK (temp outDir) |
| Live EKS check (9101 only) | partial | 22:29-22:34 | EKS API unreachable: the public IP changed and the cluster allows only the old /32. The stage returned `SKIPPED` (target unavailable), pushed nothing (ECR still only `v1.0.0`) and wrote audit entries. The push/rollout path was NOT run on EKS: it would need an AWS change (endpoint CIDR), and the 9101 image fails the pipeline image gate (CRITICAL zlib CVE-2023-45853, will_not_fix). `promote-verify.js` now enforces that gate. |
| Tests after | done | 22:35 | 1004 tests, 973 pass, **23 fail (same set as baseline)**, 8 skipped (+16 unit tests, +1 integration test skipped without `PROMOTE_IT=1`) |
| Docs | done | 22:36 | `docs/promote-stage.md` |

## For the destroy in the other session
The EKS API endpoint is reachable only from the old public IP, so every kubectl/helm step of Stage 7 fails from
here: deleting the LoadBalancer Services (including the real 9101 NLB), the namespaces and the Helm releases.
Refresh the allowed CIDR first: `scripts/eks-shared-plan.sh` (in ~/cs-iac), then apply that single in-place change
with the admin profile. Otherwise the NLB and its ENIs can block the VPC destroy.

## Decisions
- Settings live on `projects` (`promote_target` none|eks, `promote_approval` manual|auto_after_gates) and the result on
  `pipeline_executions.promote_result`. Migration 024 is additive. It was not run tonight because the running stack
  shares the database. Until it is applied, the stage reads "none" (no promotion), so existing behaviour cannot change.
- The stage promotes the exact image that the staging Deploy stage built, scanned and DAST-tested (`localImageId`),
  re-tagged `<ECR repo>:<commit SHA>`. It does not rebuild.
