'use strict';
// Unit tests for the "Promote to EKS" stage (services/promoteStage.js): every decision path with fake adapters.
const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../services/promoteStage');

const SHA = 'a'.repeat(40), IMG = 'sha256:' + 'b'.repeat(64), OTHER = 'sha256:' + 'c'.repeat(64);
const REG = '229032674007.dkr.ecr.ap-south-1.amazonaws.com';
const REPO = `${REG}/cloudsentinel/p-9101-app`;
const STAGES = ['SAST', 'Dependency', 'IaC', 'Deploy', 'DAST'];
const config = () => P.targetConfig({ PROMOTE_KUBE_CONTEXT: 'eks-cloudsentinel', PROMOTE_REGISTRY: REG, PROMOTE_AWS_ACCOUNT: '229032674007', PROMOTE_AWS_REGION: 'ap-south-1' });
const applied = () => ({ status: 'APPLIED', classification: { result: 'CONTAINER', components: [{ name: 'app', port: 8080 }] }, outputs: { components: { app: { repository_url: REPO } } } });
const planned = () => ({ status: 'AWAITING_APPROVAL', classification: applied().classification, plan: { hash: 'f'.repeat(64), expiresAt: new Date(Date.now() + 6e5).toISOString(), summary: [{ actions: ['create'], type: 'aws_ecr_repository', address: 'module.workload["app"].aws_ecr_repository.this' }] } });

function world(o = {}) {
  const calls = [], audit = [];
  let record = o.record || applied();
  const engine = {
    calls,
    async get() { return record; },
    async analyze() { calls.push('analyze'); record = { status: 'ANALYZED', classification: { result: o.classifyAs || 'CONTAINER', components: applied().classification.components } }; return record; },
    async confirm() { calls.push('confirm'); record = { ...record, status: 'CONFIRMED' }; return record; },
    async plan() { calls.push('plan'); if (o.planError) throw Object.assign(new Error(o.planError), { safe: true }); record = planned(); return record; },
    async approve(p, user, a) { calls.push(['approve', user, a.hash, a.approvedBy]); record = { ...record, approval: { userId: user, approvedBy: a.approvedBy } }; return record; },
    async apply(p, user) { calls.push(['apply', user]); if (o.applyError) throw Object.assign(new Error('apply failed; operator review required (no retry)'), { safe: true }); record = applied(); return record; },
    gate() { return o.gate || { enabled: true, reasons: [] }; },
    async artifacts(p, { tag }) { calls.push(['artifacts', tag]); return [{ component: 'app', manifests: { namespace: 'cloudsentinel-p-9101', name: 'p9101-app', yaml: `image: ${REPO}:${tag}\n` } }]; },
  };
  const kube = {
    deployed: o.deployed || null,
    async reachable() { calls.push('reachable'); return o.reachable !== false; },
    async deployedImage() { return this.deployed; },
    async apply(yaml, { dryRun }) { calls.push(dryRun ? 'dry-run' : 'apply-manifests'); if (dryRun && o.denied) throw Object.assign(new Error('admission webhook denied'), { safe: true }); if (!dryRun) this.deployed = /image: (\S+)/.exec(yaml)[1]; },
    async rollout() { calls.push('rollout'); return o.rolloutFails ? { ok: false, detail: 'progress deadline exceeded' } : { ok: true, detail: 'successfully rolled out' }; },
    async undo() { calls.push('undo'); return { ok: true, detail: 'rolled back' }; },
    async health() { calls.push('health'); return o.unhealthy ? { ok: false, detail: 'HTTP 500' } : { ok: true, detail: 'GET / -> 200 via port-forward' }; },
  };
  const registry = {
    async describe() { calls.push('describe'); return o.existing || { exists: false }; },
    async push(id, ref) { calls.push(['push', id, ref]); if (o.pushError) throw o.pushError; },
  };
  const deps = { engine, kube, registry, config: o.config || config(), required: STAGES, audit: async e => { audit.push(e); } };
  const ctx = { project: { id: 9101 }, executionId: 7, settings: o.settings || { target: 'eks', approval: 'manual' }, stagesCompleted: o.stages || STAGES, earlierFailed: !!o.earlierFailed, image: o.image || { localImageId: IMG, sourceCommit: SHA } };
  return { ctx, deps, calls, audit, run: () => P.promote(ctx, deps) };
}
const flat = calls => calls.map(c => Array.isArray(c) ? c[0] : c);

test('all earlier stages passed, infrastructure applied: tag = commit SHA, push, dry run, apply, rollout, health', async () => {
  const w = world(), r = await w.run();
  assert.equal(r.status, 'PROMOTED');
  assert.equal(r.tag, SHA); assert.equal(r.image, `${REPO}:${SHA}`);
  assert.deepEqual(flat(w.calls), ['reachable', 'artifacts', 'describe', 'push', 'dry-run', 'apply-manifests', 'rollout', 'health']);
  assert.deepEqual(w.calls.find(c => c[0] === 'push'), ['push', IMG, `${REPO}:${SHA}`]);
  assert.ok(!JSON.stringify(r).includes(':latest'));
  const actions = w.audit.map(a => a.action);
  for (const a of ['promote-start', 'promote-push', 'promote-apply', 'promote-rollout', 'promote-result']) assert.ok(actions.includes(a), a);
  assert.ok(w.audit.every(a => a.executionId === 7 && a.by === 'pipeline:execution-7'));
});

test('an earlier stage failed or is missing: the stage does not run (fail closed)', async () => {
  for (const o of [{ stages: ['SAST', 'Dependency', 'IaC', 'Deploy'] }, { earlierFailed: true }, { stages: [] }]) {
    const w = world(o), r = await w.run();
    assert.equal(r.status, 'NOT_RUN');
    assert.deepEqual(w.calls, []);
  }
  const active = P.requiredStages({ DAST_ACTIVE_ENABLED: 'true' });
  assert.ok(active.includes('Active DAST'));
});

test('promote_target none: nothing runs and nothing is recorded (existing behaviour)', async () => {
  const w = world({ settings: { target: 'none', approval: 'manual' } }), r = await w.run();
  assert.equal(r.status, 'NOT_CONFIGURED'); assert.deepEqual(w.calls, []); assert.deepEqual(w.audit, []);
  assert.deepEqual(P.settingsFrom(undefined), { target: 'none', approval: 'manual' });
  assert.deepEqual(P.settingsFrom({ promote_target: 'EKS', promote_approval: 'auto' }), { target: 'none', approval: 'manual' });
  // migration 024 not applied, DB error or mocked pool: runForPipeline returns null and writes nothing
  for (const pool of [{ query: async () => { throw Object.assign(new Error('column'), { code: '42703' }); } }, { query: async () => { throw new Error('down'); } }, { query: async () => ({}) }]) {
    assert.equal(await P.runForPipeline({ pool, projectId: 9101, executionId: 7, userId: 4, stagesCompleted: STAGES, deployResult: {} }), null);
  }
});

test('infrastructure not applied, approval manual: generate + plan + allowlist, show the plan, stop "infrastructure approval required"', async () => {
  const w = world({ record: { status: 'NONE' } }), r = await w.run();
  assert.equal(r.status, 'APPROVAL_REQUIRED'); assert.equal(r.reason, 'infrastructure approval required');
  assert.deepEqual(flat(w.calls), ['analyze', 'confirm', 'plan']);
  assert.equal(r.plan.hash, 'f'.repeat(64)); assert.equal(r.plan.allowlist, 'ACCEPTED'); assert.equal(r.plan.resources.length, 1);
  assert.ok(w.audit.some(a => a.action === 'promote-infrastructure-approval-required'));
});

test('second run while a plan awaits manual approval reuses that plan (idempotent)', async () => {
  const w = world({ record: planned() }), r = await w.run();
  assert.equal(r.status, 'APPROVAL_REQUIRED'); assert.deepEqual(w.calls, []);
});

test('auto_after_gates + allowlist pass: approve the exact plan hash as "pipeline gates", apply, then deploy', async () => {
  const w = world({ record: { status: 'NONE' }, settings: { target: 'eks', approval: 'auto_after_gates' } }), r = await w.run();
  assert.equal(r.status, 'PROMOTED'); assert.equal(r.approvedBy, 'pipeline gates');
  const approve = w.calls.find(c => c[0] === 'approve');
  assert.deepEqual(approve, ['approve', 'pipeline:execution-7', 'f'.repeat(64), 'pipeline gates (execution 7)']);
  assert.deepEqual(w.calls.find(c => c[0] === 'apply'), ['apply', 'pipeline:execution-7']);
  assert.ok(w.audit.some(a => a.action === 'promote-result' && a.approvedBy === 'pipeline gates'));
});

test('auto_after_gates + allowlist reject: stop and ask a human; nothing approved or applied', async () => {
  const w = world({ record: { status: 'NONE' }, settings: { target: 'eks', approval: 'auto_after_gates' }, planError: 'Plan rejected: UNEXPECTED_RESOURCE_TYPE' }), r = await w.run();
  assert.equal(r.status, 'NEEDS_REVIEW'); assert.match(r.reason, /allowlist rejected.*UNEXPECTED_RESOURCE_TYPE.*human/);
  assert.ok(!flat(w.calls).includes('approve') && !flat(w.calls).includes('apply') && !flat(w.calls).includes('push'));
});

test('auto_after_gates still honours INFRA_APPLY_ENABLED and the kill switch; apply failure fails the stage', async () => {
  const off = world({ record: { status: 'NONE' }, settings: { target: 'eks', approval: 'auto_after_gates' }, gate: { enabled: false, reasons: ['Kill switch file present'] } });
  const r = await off.run();
  assert.equal(r.status, 'NEEDS_REVIEW'); assert.match(r.reason, /Kill switch/); assert.ok(!flat(off.calls).includes('approve'));
  const bad = world({ record: { status: 'NONE' }, settings: { target: 'eks', approval: 'auto_after_gates' }, applyError: true });
  const b = await bad.run();
  assert.equal(b.status, 'FAILED'); assert.match(b.reason, /infrastructure apply failed/); assert.ok(!flat(bad.calls).includes('push'));
  const plan = world({ record: { status: 'NONE' }, planError: 'Terraform plan failed; nothing applied' });
  assert.equal((await plan.run()).status, 'FAILED');
  const uncertain = world({ record: { status: 'NONE' }, classifyAs: 'CONFIRM_ENTRYPOINT' });
  assert.equal((await uncertain.run()).status, 'NEEDS_REVIEW');
  const busy = world({ record: { status: 'NEEDS_OPERATOR_REVIEW' } });
  assert.equal((await busy.run()).status, 'NEEDS_REVIEW'); assert.deepEqual(busy.calls, []);
});

test('target unreachable or not configured: "skipped: target unavailable", nothing pushed', async () => {
  const w = world({ reachable: false }), r = await w.run();
  assert.equal(r.status, 'SKIPPED'); assert.match(r.reason, /^target unavailable/); assert.deepEqual(flat(w.calls), ['reachable']);
  for (const env of [{}, { PROMOTE_KUBE_CONTEXT: 'x', PROMOTE_REGISTRY: '111111111111.dkr.ecr.ap-south-1.amazonaws.com', PROMOTE_AWS_ACCOUNT: '111111111111', PROMOTE_AWS_REGION: 'ap-south-1' }, { PROMOTE_KUBE_CONTEXT: 'x', PROMOTE_REGISTRY: REG, PROMOTE_AWS_ACCOUNT: '229032674007', PROMOTE_AWS_REGION: 'us-east-1' }]) {
    const c = world({ config: P.targetConfig(env) }), s = await c.run();
    assert.equal(s.status, 'SKIPPED'); assert.deepEqual(c.calls, []);
  }
});

test('push conflict: tag exists with a different image -> refuse to overwrite, stage failed, nothing applied', async () => {
  const w = world({ existing: { exists: true, configDigest: OTHER } }), r = await w.run();
  assert.equal(r.status, 'FAILED'); assert.match(r.reason, /already exists.*refusing to overwrite/);
  assert.ok(!flat(w.calls).includes('push') && !flat(w.calls).includes('apply-manifests'));
  const race = world({ pushError: Object.assign(new Error('tag already exists (immutable)'), { safe: true, code: 'TAG_EXISTS' }) });
  assert.equal((await race.run()).status, 'FAILED');
  const expired = world({ pushError: Object.assign(new Error('AWS login for profile cloudsentinel-dev has expired; run: aws login --profile cloudsentinel-dev'), { safe: true, code: 'CREDENTIALS_EXPIRED' }) });
  const e = await expired.run();
  assert.equal(e.status, 'NEEDS_REVIEW'); assert.match(e.reason, /aws login --profile cloudsentinel-dev/);
});

test('rerun with the same commit: same image -> no push, re-apply is a no-op; rebuilt image already deployed -> ALREADY_PROMOTED', async () => {
  const same = world({ existing: { exists: true, configDigest: IMG } }), r = await same.run();
  assert.equal(r.status, 'PROMOTED'); assert.ok(!flat(same.calls).includes('push'));
  const again = world({ existing: { exists: true, configDigest: OTHER }, deployed: `${REPO}:${SHA}` }), a = await again.run();
  assert.equal(a.status, 'ALREADY_PROMOTED'); assert.ok(!flat(again.calls).includes('apply-manifests'));
});

test('rollout failure -> kubectl rollout undo, stage failed; health failure also rolls back', async () => {
  const w = world({ rolloutFails: true, deployed: `${REPO}:${'9'.repeat(40)}` }), r = await w.run();
  assert.equal(r.status, 'FAILED'); assert.equal(r.rolledBack, true); assert.match(r.reason, /rollout failed; rollback done/);
  assert.ok(flat(w.calls).includes('undo'));
  assert.ok(w.audit.some(a => a.action === 'promote-rollback' && a.result === 'ROLLED_BACK' && a.restoredImage === `${REPO}:${'9'.repeat(40)}`));
  const h = world({ unhealthy: true, deployed: `${REPO}:${'9'.repeat(40)}` }), hr = await h.run();
  assert.equal(hr.status, 'FAILED'); assert.ok(flat(h.calls).includes('undo'));
  const first = world({ rolloutFails: true }), fr = await first.run();
  assert.equal(fr.status, 'FAILED'); assert.match(fr.reason, /no previous revision/); assert.ok(!flat(first.calls).includes('undo'));
});

test('admission (Kyverno) dry-run denial stops before apply; missing image identity fails; multi-component needs review', async () => {
  const w = world({ denied: true }), r = await w.run();
  assert.equal(r.status, 'FAILED'); assert.ok(!flat(w.calls).includes('apply-manifests'));
  assert.equal((await world({ image: { localImageId: IMG, sourceCommit: 'latest' } }).run()).status, 'FAILED');
  const three = applied(); three.classification.components = [{ name: 'backend', port: 8000 }, { name: 'frontend', port: 3000 }];
  assert.equal((await world({ record: three }).run()).status, 'NEEDS_REVIEW');
});

test('ECR adapter: password only on stdin, private DOCKER_CONFIG, immutable-tag error and expiry mapped', async () => {
  const seen = [];
  const run = async (file, args, opts) => {
    seen.push({ file, args, input: opts.input, env: opts.env });
    if (args[1] === 'get-login-password') return { code: 0, stdout: 'SECRET-PASSWORD-XYZ\n', stderr: '' };
    if (args[0] === 'push') return { code: 1, stdout: '', stderr: "tag invalid: The image tag 'x' already exists ... immutable" };
    return { code: 0, stdout: '{}', stderr: '' };
  };
  const ecr = P.ecrAdapter(config(), { run, aws: 'aws', docker: 'docker' });
  await assert.rejects(ecr.push(IMG, `${REPO}:${SHA}`), e => e.code === 'TAG_EXISTS');
  assert.ok(seen.every(s => !s.args.join(' ').includes('SECRET-PASSWORD-XYZ')));
  const login = seen.find(s => s.args[0] === 'login');
  assert.equal(login.input, 'SECRET-PASSWORD-XYZ'); assert.match(login.env.DOCKER_CONFIG, /cs-promote-docker-/);
  assert.equal(seen.find(s => s.args[1] === 'get-login-password').env.AWS_PROFILE, 'cloudsentinel-dev');
  const exp = P.ecrAdapter(config(), { run: async () => ({ code: 255, stdout: '', stderr: 'Your session has expired. Please reauthenticate using aws login' }), aws: 'aws' });
  await assert.rejects(exp.describe(REPO, SHA), e => e.code === 'CREDENTIALS_EXPIRED');
  const nf = P.ecrAdapter(config(), { run: async () => ({ code: 0, stdout: JSON.stringify({ images: [], failures: [{ failureCode: 'ImageNotFound' }] }), stderr: '' }) });
  assert.deepEqual(await nf.describe(REPO, SHA), { exists: false });
  const found = P.ecrAdapter(config(), { run: async () => ({ code: 0, stdout: JSON.stringify({ images: [{ imageManifest: JSON.stringify({ config: { digest: IMG } }) }] }), stderr: '' }) });
  assert.deepEqual(await found.describe(REPO, SHA), { exists: true, configDigest: IMG });
  await assert.rejects(P.ecrAdapter(config(), { run }).describe('evil.example.com/x', SHA), e => e.code === 'REGISTRY');
});

test('kube adapter always passes the explicit --context and never changes the default context', async () => {
  const seen = [];
  const kube = P.kubeAdapter(config(), { run: async (f, a) => { seen.push(a); return { code: 0, stdout: 'ok', stderr: '' }; } });
  await kube.reachable(); await kube.apply('kind: Namespace\n', { dryRun: true }); await kube.rollout('ns', 'd', 60); await kube.undo('ns', 'd', 60);
  assert.ok(seen.every(a => a[0] === '--context' && a[1] === 'eks-cloudsentinel'));
  assert.ok(!seen.some(a => a.includes('use-context') || a.includes('config')));
  assert.ok(seen.some(a => a.includes('--dry-run=server')));
});

test('runForPipeline records the result on the execution and fails closed on unexpected errors', async () => {
  const queries = [];
  const pool = { query: async (sql, params) => { queries.push([sql, params]); if (/FROM projects WHERE id=\$1$/.test(sql.trim())) return { rows: [{ promote_target: 'eks', promote_approval: 'manual' }] }; if (/FROM projects WHERE id = \$1 AND user_id/.test(sql) || /FROM projects/.test(sql)) return { rows: [] }; return { rows: [] }; } };
  const r = await P.runForPipeline({ pool, projectId: 9101, executionId: 7, userId: 4, stagesCompleted: STAGES, deployResult: { localImageId: IMG, sourceCommit: SHA }, deps: { config: config() } });
  assert.equal(r.status, 'FAILED'); assert.match(r.reason, /promote stage error/);
  const write = queries.find(q => /SET promote_result/.test(q[0]));
  assert.ok(write); assert.equal(JSON.parse(write[1][0]).status, 'FAILED');
});
