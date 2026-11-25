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
| Minikube integration test | | | |
| Frontend stage view | | | |
| Live EKS check (9101 only) | | | |
| Docs | | | |

## Decisions
- Settings live on `projects` (`promote_target` none|eks, `promote_approval` manual|auto_after_gates) and the result on
  `pipeline_executions.promote_result`. Migration 024 is additive. It was not run tonight because the running stack
  shares the database. Until it is applied, the stage reads "none" (no promotion), so existing behaviour cannot change.
- The stage promotes the exact image that the staging Deploy stage built, scanned and DAST-tested (`localImageId`),
  re-tagged `<ECR repo>:<commit SHA>`. It does not rebuild.
