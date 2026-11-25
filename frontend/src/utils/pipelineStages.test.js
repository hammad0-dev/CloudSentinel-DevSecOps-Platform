import test from "node:test";
import assert from "node:assert/strict";
import { BASE_STAGES, pipelineStageList, promoteStageView } from "./pipelineStages.js";

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
