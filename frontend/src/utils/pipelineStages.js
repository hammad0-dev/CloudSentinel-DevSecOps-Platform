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

// Identifiers that should not be shown on the page (stage reasons come from the backend and can name the
// approved AWS account, registry or cluster). Masked before truncation so a cut can never leave half a value.
const MASKS = [
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "<access-key>"],
  // AWS hostnames that name a resource (EKS endpoint, load balancer, database, cache). Plain service endpoints and
  // the ECR registry name (its account ID is masked by the next rule) stay readable.
  [/\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.amazonaws\.com\b/gi, (h) => (/\.dkr\.ecr\./i.test(h) || !/(^|\.)(eks|elb|rds|elasticache|es|cache)(\.|$)/i.test(h.replace(/\.amazonaws\.com$/i, ""))) ? h : "<aws-host>"],
  [/\b\d{12}(?=\.dkr\.ecr\.)/g, "<account-id>"],
  [/(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)\d{12}(?=:)/gi, "$1<account-id>"],
  [/(?<![A-Za-z0-9.])\d{12}(?![A-Za-z0-9.])/g, "<account-id>"],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "<email>"],
];
export function maskIdentifiers(text) {
  return MASKS.reduce((s, [re, to]) => s.replace(re, to), String(text ?? ""));
}

// What the Promote node shows: status label, the stage's reason, the image tag (short commit) and the plan summary
// when infrastructure approval is required.
export function promoteStageView(result) {
  const r = parse(result);
  if (!r) return null;
  const plan = r.plan && Array.isArray(r.plan.resources)
    ? `Plan ${String(r.plan.hash || "").slice(0, 12)}: ${r.plan.resources.length} resources (allowlist ${maskIdentifiers(r.plan.allowlist || "?")})`
    : null;
  return {
    status: LABELS[r.status] || "Pending",
    raw: String(r.status || ""),
    detail: maskIdentifiers(r.reason || "").slice(0, 200),
    tag: r.tag ? String(r.tag).slice(0, 12) : null,
    plan,
    approvedBy: r.approvedBy ? maskIdentifiers(r.approvedBy).slice(0, 100) : null,
    rolledBack: r.rolledBack === true,
  };
}
