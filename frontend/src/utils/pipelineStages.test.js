import test from "node:test";
import assert from "node:assert/strict";
import { BASE_STAGES, pipelineStageList, promoteStageView, maskIdentifiers } from "./pipelineStages.js";

test("Promote appears only when the execution has a promote result", () => {
  assert.deepEqual(pipelineStageList({ stages_completed: "SAST, Dependency" }), BASE_STAGES);
  assert.deepEqual(pipelineStageList({ promote_result: null }), BASE_STAGES);
  assert.deepEqual(pipelineStageList({ promote_result: { status: "SKIPPED" } }), [...BASE_STAGES, "Promote"]);
  assert.deepEqual(pipelineStageList({ promote_result: "not json" }), BASE_STAGES);
});

test("Promote node labels every stage outcome", () => {
  const cases = { PROMOTED: "Passed", ALREADY_PROMOTED: "Passed", FAILED: "Failed", APPROVAL_REQUIRED: "Approval required", NEEDS_REVIEW: "Needs review", SKIPPED: "Skipped", NOT_RUN: "Skipped", WEIRD: "Pending" };
  for (const [status, label] of Object.entries(cases)) assert.equal(promoteStageView({ status }).status, label);
  const v = promoteStageView(JSON.stringify({ status: "APPROVAL_REQUIRED", reason: "infrastructure approval required", tag: "a".repeat(40), plan: { hash: "f".repeat(64), allowlist: "ACCEPTED", resources: [{}, {}, {}] } }));
  assert.equal(v.detail, "infrastructure approval required");
  assert.equal(v.tag, "aaaaaaaaaaaa");
  assert.equal(v.plan, "Plan ffffffffffff: 3 resources (allowlist ACCEPTED)");
  assert.equal(promoteStageView(null), null);
});

test("Promote node masks the AWS account ID and similar identifiers", () => {
  // the exact reason the stage produced in the e2e run (execution 113)
  const reason = "target unavailable: PROMOTE_KUBE_CONTEXT not set; PROMOTE_AWS_ACCOUNT must be the approved account 229032674007; PROMOTE_AWS_REGION must be ap-south-1; PROMOTE_REGISTRY must be the ECR registry of that account and region";
  const v = promoteStageView({ status: "SKIPPED", reason, approvedBy: "ops@example.org" });
  assert.equal(v.status, "Skipped");
  assert.doesNotMatch(v.detail, /\d{12}/);
  assert.match(v.detail, /approved account <account-id>; PROMOTE_AWS_REGION must be ap-south-1/);
  assert.equal(v.approvedBy, "<email>");
  const cases = {
    "push to 229032674007.dkr.ecr.ap-south-1.amazonaws.com/cloudsentinel/p-9101-app failed": "push to <account-id>.dkr.ecr.ap-south-1.amazonaws.com/cloudsentinel/p-9101-app failed",
    "role arn:aws:iam::229032674007:role/cloudsentinel-p9101-app-irsa denied": "role arn:aws:iam::<account-id>:role/cloudsentinel-p9101-app-irsa denied",
    "endpoint ABCDEF0123456789ABCDEF0123456789.gr7.ap-south-1.eks.amazonaws.com unreachable": "endpoint <aws-host> unreachable",
    "lb a3c86b0000-1234567890.elb.ap-south-1.amazonaws.com pending": "lb <aws-host> pending",
    "db cloudsentinel-p9102-db.abc123xyz.ap-south-1.rds.amazonaws.com": "db <aws-host>",
    "key AKIAIOSFODNN7EXAMPLE leaked": "key <access-key> leaked",
  };
  for (const [input, want] of Object.entries(cases)) assert.equal(maskIdentifiers(input), want, input);
  // not identifiers: hashes, commit tags, timestamps, region names and short numbers stay as they are
  for (const keep of ["Plan ffffffffffff: 3 resources", "tag 14320fce1234", "1795633687591 ms", "ap-south-1", "execution 113", "sha256:" + "a".repeat(64), "sha256:ab123456789012cd" + "e".repeat(48)]) assert.equal(maskIdentifiers(keep), keep);
});
