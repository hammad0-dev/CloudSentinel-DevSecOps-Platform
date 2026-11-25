// Pipeline stage list for the CI/CD view. "Promote" (promote to EKS) is shown only when the execution has a
// promote_result, so projects with promote_target=none look exactly as before.
export const BASE_STAGES = ["SAST", "Dependency", "IaC", "Deploy", "DAST"];

const LABELS = {
  PROMOTED: "Passed",
  ALREADY_PROMOTED: "Passed",
  FAILED: "Failed",
  APPROVAL_REQUIRED: "Approval required",
  NEEDS_REVIEW: "Needs review",
  SKIPPED: "Skipped",
  NOT_RUN: "Skipped",
};

function parse(result) {
  if (!result) return null;
  if (typeof result === "string") {
    try { return JSON.parse(result); } catch { return null; }
  }
  return typeof result === "object" ? result : null;
}

export function pipelineStageList(pipeline) {
  return parse(pipeline?.promote_result) ? [...BASE_STAGES, "Promote"] : BASE_STAGES;
}

// What the Promote node shows: status label, the stage's reason, the image tag (short commit) and the plan summary
// when infrastructure approval is required.
export function promoteStageView(result) {
  const r = parse(result);
  if (!r) return null;
  const plan = r.plan && Array.isArray(r.plan.resources)
    ? `Plan ${String(r.plan.hash || "").slice(0, 12)}: ${r.plan.resources.length} resources (allowlist ${r.plan.allowlist || "?"})`
    : null;
  return {
    status: LABELS[r.status] || "Pending",
    raw: String(r.status || ""),
    detail: String(r.reason || "").slice(0, 200),
    tag: r.tag ? String(r.tag).slice(0, 12) : null,
    plan,
    approvedBy: r.approvedBy || null,
    rolledBack: r.rolledBack === true,
  };
}
