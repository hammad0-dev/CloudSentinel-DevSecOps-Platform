'use strict';
// Real-tool check of the generated folders (needs terraform, trivy and the provider in TF_PLUGIN_CACHE_DIR):
//   EKS_TF_TEST=1 TF_PLUGIN_CACHE_DIR=/mnt/d/cs-data/tf-plugin-cache TRIVY_CACHE_DIR=/mnt/d/cs-data/trivy-cache \
//     node --test test/eks-terraform.test.js
// For one-tier, two-tier (PostgreSQL), two-tier (MySQL) and three-tier: terraform fmt -check, init -backend=false,
// validate; Trivy config over the generated Terraform and the generated Kubernetes manifests must report no CRITICAL.
// Writes a findings summary to $EKS_TF_REPORT when set.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), os = require('node:os'), path = require('node:path');
const { execFileSync } = require('node:child_process');
const W = require('../services/eksWorkload');
const { generateEksManifests } = require('../services/eksManifests');

const enabled = process.env.EKS_TF_TEST === '1';
// A snap-packaged Trivy has a private /tmp, so the generated folders go to EKS_TF_WORKDIR (default /mnt/d/cs-data/tmp
// when present, else the OS temp dir).
const WORKDIR = process.env.EKS_TF_WORKDIR || (require('node:fs').existsSync('/mnt/d/cs-data/tmp') ? '/mnt/d/cs-data/tmp' : os.tmpdir());
const FIX = path.resolve(__dirname, '../../test-fixtures');
const run = (exe, args, cwd) => execFileSync(exe, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, TF_IN_AUTOMATION: '1', CHECKPOINT_DISABLE: '1' }, maxBuffer: 64 * 1024 * 1024 });
const report = [];
function trivy(dir, tfvars) {
  // --tf-vars is required for the generated Terraform: without it Trivy does not expand the for_each/count modules.
  const args = ['config', '--quiet', '--format', 'json', ...(tfvars ? ['--tf-vars', tfvars] : []), ...(process.env.TRIVY_CACHE_DIR ? ['--cache-dir', process.env.TRIVY_CACHE_DIR] : []), dir];
  const out = JSON.parse(run('trivy', args, dir));
  const findings = (out.Results || []).flatMap(r => (r.Misconfigurations || []).filter(m => m.Status === 'FAIL').map(m => ({ file: r.Target, id: m.ID || m.AVDID, severity: m.Severity, title: m.Title })));
  const checks = (out.Results || []).reduce((n, r) => n + (r.MisconfSummary?.Successes || 0) + (r.MisconfSummary?.Failures || 0), 0);
  return { findings, checks, targets: (out.Results || []).map(r => r.Target) };
}
const counts = f => f.reduce((c, x) => ({ ...c, [x.severity]: (c[x.severity] || 0) + 1 }), {});

const cases = [
  ['one-tier', 'cloudsentinel-test-python-clean', 51],
  ['two-tier-postgres', 'cloudsentinel-test-flask-postgres', 52],
  ['two-tier-mysql', 'cloudsentinel-test-flask-postgres', 54, 'mysql'], // same app, MySQL engine selected
  ['three-tier', 'cloudsentinel-test-three-tier', 53],
];

for (const [name, fixture, id, engine] of cases) {
  test(`generated ${name} folder passes fmt, init -backend=false, validate and Trivy (no CRITICAL)`, { skip: !enabled && 'set EKS_TF_TEST=1' }, async t => {
    const dir = await fs.mkdtemp(path.join(WORKDIR, `cs-eks-tf-${name}-`)); t.after(() => fs.rm(dir, { recursive: true, force: true }));
    const c = W.classify(await W.localSource(path.join(FIX, fixture)));
    if (engine) c.database.engine = engine;
    const { root } = await W.generate(dir, W.buildTfvars(id, c));
    run('terraform', ['fmt', '-check', '-recursive', dir], root);
    const tf = trivy(dir, path.join(root, 'terraform.tfvars.json'));
    assert.ok(tf.targets.some(x => x.endsWith('project-workload/main.tf')), 'Trivy evaluated the workload module');
    if (c.database) assert.ok(tf.targets.some(x => x.endsWith('project-database/main.tf')), 'Trivy evaluated the database module');
    run('terraform', ['init', '-backend=false', '-input=false', '-no-color', '-lockfile=readonly'], root);
    assert.match(run('terraform', ['validate', '-no-color'], root), /Success/);
    // Manifests rendered with placeholder outputs of the right shape.
    const mdir = path.join(dir, 'manifests'); await fs.mkdir(mdir);
    for (const comp of c.components) {
      const outputs = { repository_url: `229032674007.dkr.ecr.ap-south-1.amazonaws.com/cloudsentinel/p-${id}-${comp.name}`, role_arn: `arn:aws:iam::229032674007:role/cloudsentinel-p${id}-${comp.name}-irsa`, secret_name: `cloudsentinel/p-${id}/${comp.name}`, service_account: `p${id}-${comp.name}`, namespace: `cloudsentinel-p-${id}` };
      const database = c.database ? { address: `cloudsentinel-p${id}-db.abcdefghij12.ap-south-1.rds.amazonaws.com`, port: 5432, db_name: 'app', engine: c.database.engine, master_user_secret_arn: 'arn:aws:secretsmanager:ap-south-1:229032674007:secret:rds!db-0123abcd-0123-4567-89ab-0123456789ab-AbC123' } : null;
      const m = generateEksManifests({ projectId: id, component: comp, outputs, database, tag: 'v1.0.0', backendHost: comp.name === 'frontend' ? `p${id}-backend` : null });
      await fs.writeFile(path.join(mdir, `${comp.name}.yaml`), m.yaml);
      if (comp.dockerfile === 'generated') await fs.writeFile(path.join(mdir, `Dockerfile.${comp.name}`), W.generateDockerfile(comp));
    }
    const k8s = trivy(mdir);
    report.push({ case: name, terraform: { checks: tf.checks, failed: counts(tf.findings), findings: tf.findings }, manifests: { checks: k8s.checks, failed: counts(k8s.findings), findings: k8s.findings } });
    assert.ok(tf.checks > 0 && k8s.checks > 0, 'Trivy executed checks');
    assert.deepEqual(tf.findings.filter(f => f.severity === 'CRITICAL'), []);
    assert.deepEqual(k8s.findings.filter(f => f.severity === 'CRITICAL'), []);
  });
}

test.after(async () => { if (enabled && process.env.EKS_TF_REPORT) await fs.writeFile(process.env.EKS_TF_REPORT, JSON.stringify(report, null, 2)); });
