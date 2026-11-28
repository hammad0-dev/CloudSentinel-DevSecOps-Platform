// Cloud page eligibility view (execution 123: evidence "expired" one minute after every run).
const assert = require('node:assert/strict');
const test = require('node:test');
const { view } = require('../services/eligibilityView');

const now = Date.parse('2026-11-26T21:00:00Z');
const pending = { executionId: 123, decision: 'PENDING_EVIDENCE', evidence: { reasons: ['APPROVED_POLICY_MISSING_OR_EXPIRED', 'EXECUTION_REVISION_AND_ARTIFACT_BINDING_MISSING'] }, createdAt: '2026-11-26T20:11:03Z', expiresAt: '2026-11-26T20:12:03Z' };

test('never-eligible decision keeps its real reasons after the 60 s placeholder passes', () => {
  const v = view(pending, { now, policy: null });
  assert.equal(v.decision, 'PENDING_EVIDENCE');
  assert.deepEqual(v.reasons, pending.evidence.reasons);
  assert.equal(v.expiresAt, null);
  assert.equal(v.evidenceWindow.seconds, null);
  assert.match(v.evidenceWindow.source, /No approved deployment policy/);
  assert.equal(v.awsDeployment, 'NOT_STARTED');
});

test('ELIGIBLE decision still expires at the policy window and becomes BLOCKED', () => {
  const policy = { maxAgeSeconds: 900 };
  const fresh = view({ ...pending, decision: 'ELIGIBLE', evidence: { reasons: [] }, expiresAt: new Date(now + 1000) }, { now, policy });
  assert.equal(fresh.decision, 'ELIGIBLE'); assert.equal(fresh.evidenceWindow.seconds, 900); assert.equal(fresh.expired, false);
  const old = view({ ...pending, decision: 'ELIGIBLE', evidence: { reasons: [] }, expiresAt: '2026-11-26T20:12:03Z' }, { now, policy });
  assert.equal(old.decision, 'BLOCKED'); assert.match(old.reasons[0], /^Eligibility expired/);
  assert.equal(view({ ...pending, decision: 'ELIGIBLE', expiresAt: 'garbage' }, { now, policy }).decision, 'BLOCKED');
});

test('private evidence fields are not exposed', () => {
  const v = view({ ...pending, evidence: { reasons: ['X'], secret: 'HIDDEN', binding: { commit_sha: 'c' } } }, { now, policy: null });
  assert.ok(!JSON.stringify(v).includes('HIDDEN')); assert.ok(!JSON.stringify(v).includes('commit_sha'));
});

test('Cloud page shows the window or why no expiry applies, never a stale "expired"', () => {
  const fs = require('node:fs'), Module = require('node:module'), path = require('node:path');
  const file = path.resolve(__dirname, '../../frontend/src/components/DeploymentEligibility.jsx');
  const source = require('esbuild').transformSync(fs.readFileSync(file, 'utf8'), { loader: 'jsx', format: 'cjs', jsx: 'automatic' }).code;
  const m = new Module(file, module); m.paths = module.paths; m.require = id => (id === '../lib/api' ? {} : require(id)); m._compile(source, file);
  const React = require('react'), { renderToStaticMarkup } = require('react-dom/server');
  const none = renderToStaticMarkup(React.createElement(m.exports.EligibilityStatus, { result: view(pending, { now, policy: null }) }));
  assert.match(none, /Evidence expiry: not applicable/); assert.doesNotMatch(none, /Evidence expires:/);
  const live = renderToStaticMarkup(React.createElement(m.exports.EligibilityStatus, { result: view({ ...pending, decision: 'ELIGIBLE', evidence: { reasons: [] }, expiresAt: new Date(now + 1000) }, { now, policy: { maxAgeSeconds: 900 } }) }));
  assert.match(live, /Evidence expires: .*window 15 min/);
});
