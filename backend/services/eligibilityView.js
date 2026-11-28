'use strict';
// Cloud page view of the latest deployment eligibility decision.
// The evidence window is the approved policy's maxAgeSeconds (backend/docs/deployment-eligibility.md: "Expiry is
// bounded by the policy and oldest evidence"). Expiry only turns an ELIGIBLE decision into BLOCKED. A decision
// that was never eligible (no approved policy -> PENDING_EVIDENCE, or BLOCKED/UNSUPPORTED) keeps its own reasons:
// the evaluator's 60-second fallback when no policy is loaded is a storage placeholder, not an evidence window,
// and showing "Eligibility expired" a minute after every run hid the real reasons.
const { policyFromEnvironment } = require('./deploymentEligibility');

function window(policy) {
  if (policy && Number.isSafeInteger(policy.maxAgeSeconds)) return { seconds: policy.maxAgeSeconds, source: 'approved deployment policy (maxAgeSeconds)' };
  return { seconds: null, source: 'No approved deployment policy is configured (DEPLOYMENT_ELIGIBILITY_POLICY_FILE), so no decision can become eligible and no evidence window applies.' };
}

function view(row, { now = Date.now(), policy } = {}) {
  if (policy === undefined) { try { policy = policyFromEnvironment(); } catch { policy = null; } }
  const reasons = Array.isArray(row.evidence?.reasons) ? row.evidence.reasons : [];
  const base = { executionId: row.executionId, createdAt: row.createdAt, evidenceWindow: window(policy), awsDeployment: 'NOT_STARTED' };
  if (row.decision !== 'ELIGIBLE') return { ...base, decision: row.decision, reasons, expiresAt: null };
  const expiry = row.expiresAt instanceof Date ? row.expiresAt.getTime() : Date.parse(row.expiresAt);
  const expired = !Number.isFinite(expiry) || expiry <= now;
  return { ...base, decision: expired ? 'BLOCKED' : 'ELIGIBLE', reasons: expired ? ['Eligibility expired: the evidence is older than the policy window; run the pipeline again'] : reasons, expiresAt: row.expiresAt, expired };
}

module.exports = { view, window };
