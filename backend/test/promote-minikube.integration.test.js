'use strict';
// Integration test: the promote stage against Minikube as the stand-in target (PROMOTE_IT=1).
//   PROMOTE_IT=1 node --test test/promote-minikube.integration.test.js
// Real parts: the generated Dockerfile and EKS manifests (services/eksManifests.js), docker build, the kube adapter
// (server-side dry run through Minikube's Kyverno, apply, rollout status, port-forward health check, rollout undo).
// Stand-ins: the engine record (an APPLIED one-tier project) and the registry (`minikube image load` instead of an
// ECR push; the manifests keep the ECR image reference and imagePullPolicy IfNotPresent, so nothing is pulled).
// The namespace is rewritten to a throw-away cs-promote-it-<random> (never a cloudsentinel-p-* namespace) and is
// deleted afterwards. Only the explicit --context is used; the default kubectl context is never changed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const P = require('../services/promoteStage');
const W = require('../services/eksWorkload');
const { generateEksManifests } = require('../services/eksManifests');

const CONTEXT = process.env.PROMOTE_IT_CONTEXT || 'minikube';
const REG = '229032674007.dkr.ecr.ap-south-1.amazonaws.com';
const ID = 9901, NS = `cs-promote-it-${crypto.randomBytes(3).toString('hex')}`;
const REPO = `${REG}/cloudsentinel/p-${ID}-app`;
const FIXTURE = path.resolve(__dirname, '../../test-fixtures/cloudsentinel-test-python-clean');
const run = (f, a, o = {}) => P.exec(f, a, { env: { ...process.env }, timeout: 15 * 60 * 1000, ...o });
const sh = async (f, a, o) => { const r = await run(f, a, o); if (r.code !== 0) throw new Error(`${f} ${a.join(' ')}: ${r.stderr.slice(-400)}`); return r.stdout.trim(); };

test('promote to Minikube stand-in: deploy, idempotent rerun, failed rollout rolled back', { skip: process.env.PROMOTE_IT !== '1', timeout: 30 * 60 * 1000 }, async t => {
  const log = [];
  const source = await W.localSource(FIXTURE);
  const classification = W.classify(source);
  assert.equal(classification.result, 'CONTAINER');
  const comp = { ...classification.components[0], public: false, secretKeys: [] }; // no LoadBalancer / ESO on Minikube
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'cs-promote-it-'));
  const good = `cs-promote-it:good-${NS}`, bad = `cs-promote-it:bad-${NS}`;
  const loaded = [];
  t.after(async () => {
    await run('kubectl', ['--context', CONTEXT, 'delete', 'namespace', NS, '--wait=false']);
    for (const ref of loaded) await run('minikube', ['image', 'rm', ref]);
    for (const ref of [good, bad, ...loaded]) await run('docker', ['rmi', ref]);
    await fs.rm(tmp, { recursive: true, force: true });
  });

  // build the staging image from the generated Dockerfile (the fixture itself is not modified), plus a broken one
  await fs.writeFile(path.join(tmp, 'Dockerfile'), W.generateDockerfile(comp));
  await sh('docker', ['build', '-q', '-f', path.join(tmp, 'Dockerfile'), '-t', good, path.join(FIXTURE, comp.dir || '.')]);
  await fs.writeFile(path.join(tmp, 'Dockerfile.bad'), `FROM ${good}\nCMD ["python", "-c", "import sys; sys.exit(3)"]\n`);
  await sh('docker', ['build', '-q', '-f', path.join(tmp, 'Dockerfile.bad'), '-t', bad, tmp]);
  const goodId = await sh('docker', ['image', 'inspect', '--format={{.Id}}', good]);
  const badId = await sh('docker', ['image', 'inspect', '--format={{.Id}}', bad]);

  const record = { status: 'APPLIED', classification: { ...classification, components: [comp] }, outputs: { components: { app: {
    repository_url: REPO, role_arn: `arn:aws:iam::229032674007:role/cloudsentinel-p${ID}-app-irsa`, secret_name: `cloudsentinel/p-${ID}/app`,
    service_account: `p${ID}-app`, namespace: `cloudsentinel-p-${ID}` } }, database: null } };
  const engine = {
    async get() { return record; }, gate() { return { enabled: false, reasons: ['test'] }; },
    async artifacts(p, { tag }) { return [{ component: 'app', manifests: generateEksManifests({ projectId: ID, component: comp, outputs: record.outputs.components.app, tag }) }]; },
  };
  const tags = new Map();
  const registry = {
    async describe(repo, tag) { return tags.has(tag) ? { exists: true, configDigest: tags.get(tag) } : { exists: false }; },
    async push(id, ref) { await sh('docker', ['tag', id, ref]); await sh('minikube', ['image', 'load', ref]); loaded.push(ref); tags.set(ref.split(':').pop(), id); },
  };
  const config = { ...P.targetConfig({ PROMOTE_KUBE_CONTEXT: CONTEXT, PROMOTE_REGISTRY: REG, PROMOTE_AWS_ACCOUNT: '229032674007', PROMOTE_AWS_REGION: 'ap-south-1', PROMOTE_ROLLOUT_TIMEOUT_SECONDS: '60' }) };
  const mapped = P.kubeAdapter(config, { transform: y => y.replaceAll(`cloudsentinel-p-${ID}`, NS), mapNs: n => n === `cloudsentinel-p-${ID}` ? NS : n });
  const audit = [];
  const deps = { engine, kube: mapped, registry, config, required: ['SAST', 'Dependency', 'IaC', 'Deploy', 'DAST'], audit: async e => { audit.push(e); } };
  const ctx = (commit, id) => ({ project: { id: ID }, executionId: 1, settings: { target: 'eks', approval: 'manual' }, stagesCompleted: deps.required, image: { localImageId: id, sourceCommit: commit } });
  const A = 'a1'.repeat(20), B = 'b2'.repeat(20);

  const first = await P.promote(ctx(A, goodId), deps);
  log.push(['first', first.status, first.reason, first.steps]);
  assert.equal(first.status, 'PROMOTED', JSON.stringify(first));
  assert.equal(await mapped.deployedImage(`cloudsentinel-p-${ID}`, `p${ID}-app`), `${REPO}:${A}`);

  const again = await P.promote(ctx(A, goodId), deps);
  log.push(['rerun', again.status, again.reason, again.steps]);
  assert.equal(again.status, 'PROMOTED'); assert.equal(again.steps.find(s => s.name === 'push').outcome, 'SKIPPED');

  const broken = await P.promote(ctx(B, badId), deps);
  log.push(['broken', broken.status, broken.reason, broken.steps]);
  assert.equal(broken.status, 'FAILED'); assert.equal(broken.rolledBack, true);
  assert.equal(await mapped.deployedImage(`cloudsentinel-p-${ID}`, `p${ID}-app`), `${REPO}:${A}`, 'rolled back to the previous image');
  const healthy = await mapped.health(`cloudsentinel-p-${ID}`, `p${ID}-app`, comp.port, '/');
  assert.equal(healthy.ok, true, healthy.detail);

  const conflict = await P.promote(ctx(B, goodId), deps); // tag B exists with the broken image
  log.push(['conflict', conflict.status, conflict.reason]);
  assert.equal(conflict.status, 'FAILED'); assert.match(conflict.reason, /refusing to overwrite/);

  if (process.env.PROMOTE_IT_LOG) await fs.writeFile(process.env.PROMOTE_IT_LOG, JSON.stringify({ context: CONTEXT, namespace: NS, runs: log, audit }, null, 1));
});
