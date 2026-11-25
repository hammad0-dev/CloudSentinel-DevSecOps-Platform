#!/usr/bin/env node
'use strict';
// Run the Promote to EKS stage directly for ONE project whose infrastructure is already APPLIED (operator check of
// the "already applied" path). It is NOT a pipeline run: the earlier stages (SAST, dependency, IaC, image build and
// scan, Minikube deploy, DAST) are asserted by the operator with --earlier-stages-passed, and the image must be one
// the operator built and scanned. Same code, gates and audit log as the pipeline stage.
//
//   PROMOTE_KUBE_CONTEXT=... PROMOTE_REGISTRY=... PROMOTE_AWS_ACCOUNT=... PROMOTE_AWS_REGION=... \
//   INFRA_ARTIFACT_ROOT=... node scripts/promote-verify.js --dir <checkout> --project-id <n> \
//     --image-id sha256:<64 hex> --commit <40 hex> --earlier-stages-passed yes [--approval manual]
//
// Refuses to run unless the project record is APPLIED (it never plans or applies infrastructure). Prints the stage
// result as JSON; never prints credentials.
const path = require('node:path');
const backend = path.resolve(__dirname, '../backend');
const W = require(path.join(backend, 'services/eksWorkload'));
const P = require(path.join(backend, 'services/promoteStage'));
const { WorkloadInfrastructure } = require(path.join(backend, 'services/eksWorkloadEngine'));

function args(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 2) { if (!argv[i].startsWith('--') || argv[i + 1] === undefined) throw new Error(`bad argument ${argv[i]}`); o[argv[i].slice(2)] = argv[i + 1]; }
  return o;
}

(async () => {
  const o = args(process.argv.slice(2));
  const id = Number(o['project-id']);
  if (!Number.isSafeInteger(id) || id < 1 || !o.dir) throw new Error('--dir and --project-id are required');
  if (o['earlier-stages-passed'] !== 'yes') throw new Error('--earlier-stages-passed yes is required (operator assertion; this is not a pipeline run)');
  const dir = path.resolve(o.dir);
  const engine = new WorkloadInfrastructure({ source: () => W.localSource(dir) });
  const record = await engine.get(id);
  if (record.status !== 'APPLIED') throw new Error(`project ${id} infrastructure is ${record.status}; this check only runs the already-applied path`);
  // Same rule as the pipeline's image stage (services/imageVulnerabilityScan.js): any CRITICAL OS-package
  // vulnerability, fixed or not, blocks. The operator assertion cannot override it.
  if (!/^sha256:[a-f0-9]{64}$/.test(o['image-id'] || '')) throw new Error('--image-id sha256:<64 hex> is required');
  const scan = await P.exec(process.env.IMAGE_TRIVY_CMD || 'trivy', ['image', '--quiet', '--scanners', 'vuln', '--vuln-type', 'os', '--severity', 'CRITICAL', '--exit-code', '1', '--format', 'json',
    ...(process.env.INFRA_TRIVY_CACHE_DIR ? ['--cache-dir', process.env.INFRA_TRIVY_CACHE_DIR] : []), o['image-id']], { env: process.env, timeout: 600000 });
  if (scan.code !== 0) throw new Error(scan.code === 1 ? 'image fails the image security gate (CRITICAL OS-package vulnerability); not promoted' : 'image scan unavailable; not promoted');
  const config = P.targetConfig();
  const required = P.requiredStages({});
  const result = await P.promote({
    project: { id, user_id: 'operator' }, executionId: 0,
    settings: { target: 'eks', approval: o.approval === 'auto_after_gates' ? 'auto_after_gates' : 'manual' },
    stagesCompleted: required, image: { localImageId: o['image-id'], sourceCommit: o.commit },
  }, { engine, config, required, kube: P.kubeAdapter(config), registry: P.ecrAdapter(config), audit: e => engine.recordAudit(id, { ...e, by: 'operator:promote-verify', executionId: null }) });
  process.stdout.write(JSON.stringify(result, null, 1) + '\n');
  process.exitCode = P.SUCCESS.has(result.status) ? 0 : 1;
})().catch(e => { process.stderr.write(`promote-verify: ${e.message}\n`); process.exitCode = 2; });
