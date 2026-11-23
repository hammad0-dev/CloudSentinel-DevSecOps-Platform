'use strict';
// EKS workload generator: classification per architecture, validated tfvars, Dockerfile/manifest hardening,
// plan allowlist (rejects public RDS, extra types, missing tags, wrong account, ...) and the gated lifecycle.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const W = require('../services/eksWorkload');
const { generateEksManifests } = require('../services/eksManifests');
const { WorkloadInfrastructure, applyGate } = require('../services/eksWorkloadEngine');
const { generateK8sManifests } = require('../services/deployment');

const FIX = path.resolve(__dirname, '../../test-fixtures');
const fixture = name => W.localSource(path.join(FIX, name));
const mem = (files, code = {}) => ({ commit: 'c'.repeat(40), files, code, paths: [...Object.keys(files), ...Object.keys(code)] });

// ---- classification per architecture -------------------------------------------------------------------------
test('one-tier: python-clean is one app component, no database, entrypoint and port detected', async () => {
  const c = W.classify(await fixture('cloudsentinel-test-python-clean'));
  assert.equal(c.result, 'CONTAINER'); assert.equal(c.architecture, 'one-tier'); assert.equal(c.database, null);
  assert.deepEqual(c.components.map(x => x.name), ['app']);
  const app = c.components[0];
  assert.equal(app.stack, 'python'); assert.equal(app.framework, 'flask'); assert.equal(app.port, 8080);
  assert.deepEqual(app.entrypoint, { kind: 'python', file: 'app.py' }); assert.equal(app.dockerfile, 'generated'); assert.equal(app.public, true);
});

test('two-tier: Flask + PostgreSQL gets RDS postgres; DB settings are not project secrets', async () => {
  const c = W.classify(await fixture('cloudsentinel-test-flask-postgres'));
  assert.equal(c.result, 'CONTAINER'); assert.equal(c.architecture, 'two-tier');
  assert.deepEqual(c.database, { engine: 'postgres', name: 'app' });
  const app = c.components[0];
  assert.deepEqual(app.secretKeys, ['APP_GREETING']);
  assert.deepEqual(app.dbEnv, ['DB_HOST', 'DB_NAME', 'DB_PASSWORD', 'DB_PORT', 'DB_USER']);
  assert.equal(app.usesDatabase, true);
  const v = W.buildTfvars(42, c);
  assert.deepEqual(v, { project_id: 42, environment: 'development', cluster_name: 'cloudsentinel-eks', components: { app: { port: 8080, env_names: ['APP_GREETING'] } }, database: { engine: 'postgres', name: 'app' } });
});

test('three-tier: separate frontend (public) and backend (private) deployments plus RDS', async () => {
  const c = W.classify(await fixture('cloudsentinel-test-three-tier'));
  assert.equal(c.result, 'CONTAINER'); assert.equal(c.architecture, 'three-tier'); assert.equal(c.database.engine, 'postgres');
  const by = Object.fromEntries(c.components.map(x => [x.name, x]));
  assert.equal(by.frontend.public, true); assert.equal(by.backend.public, false);
  assert.equal(by.frontend.port, 3000); assert.equal(by.backend.port, 3001);
  assert.equal(by.frontend.usesDatabase, false); assert.equal(by.backend.usesDatabase, true);
  assert.deepEqual(Object.keys(W.buildTfvars(43, c).components).sort(), ['backend', 'frontend']);
});

test('static: HTML-only repository goes to the existing static-site engine, nothing generated here', async () => {
  const c = W.classify(await fixture('cloudsentinel-test-static-site'));
  assert.equal(c.result, 'STATIC_SITE'); assert.equal(c.template, 'static-site');
  assert.throws(() => W.buildTfvars(44, c), /confirmed container/);
});

test('custom/unknown architectures and unsupported databases return manual review, never a guess', () => {
  const custom = W.classify(mem({ 'compose.yaml': 'services:\n  a:\n    image: custom:a\n  b:\n    image: custom:b\n' }));
  assert.equal(custom.result, 'MANUAL_REVIEW'); assert.equal(custom.template, null);
  assert.equal(W.classify(mem({ 'go.mod': 'module x' })).result, 'MANUAL_REVIEW');
  assert.equal(W.classify(mem({})).result, 'MANUAL_REVIEW');
  for (const [dep, db] of [['mongoose', 'MongoDB'], ['redis', 'Redis'], ['sqlite3', 'SQLite']]) {
    const r = W.classify(mem({ 'package.json': JSON.stringify({ scripts: { start: 'node s.js' }, dependencies: { express: '4', [dep]: '1' } }) }));
    assert.equal(r.result, 'MANUAL_REVIEW', dep); assert.match(r.reason, new RegExp(db));
    assert.throws(() => W.buildTfvars(45, r));
  }
  const both = W.classify(mem({ 'requirements.txt': 'flask\npsycopg2\npymysql' }, { 'app.py': '' }));
  assert.equal(both.result, 'MANUAL_REVIEW');
  const nodb = W.classify(mem({ 'ui/package.json': JSON.stringify({ scripts: { start: 'x' }, dependencies: { react: '1' } }), 'api/package.json': JSON.stringify({ scripts: { start: 'x' }, dependencies: { express: '1' } }) }));
  assert.equal(nodb.result, 'MANUAL_REVIEW');
});

test('uncertain entrypoint returns CONFIRM_ENTRYPOINT; a confirmed file must exist in the component', () => {
  const src = mem({ 'requirements.txt': 'flask' }, { 'app.py': 'x', 'main.py': 'y' });
  const c = W.classify(src);
  assert.equal(c.result, 'CONFIRM_ENTRYPOINT'); assert.equal(c.needsConfirmation[0].field, 'entrypoint');
  assert.throws(() => W.generateDockerfile(c.components[0]), /Confirm entrypoint/);
  const ok = W.classify(src, { architecture: 'one-tier', entrypoints: { app: 'main.py' } });
  assert.equal(ok.result, 'CONTAINER'); assert.equal(ok.components[0].entrypoint.file, 'main.py');
  assert.throws(() => W.classify(src, { entrypoints: { app: 'missing.py' } }), /not a file/);
  assert.throws(() => W.classify(src, { entrypoints: { app: '../etc/x.py' } }), /not a file/);
  const node = W.classify(mem({ 'package.json': JSON.stringify({ dependencies: { express: '1' } }) }));
  assert.equal(node.result, 'CONFIRM_ENTRYPOINT'); // express backend without start/main: ask, do not guess
  assert.equal(W.classify(mem({ 'package.json': JSON.stringify({ dependencies: { lodash: '1' } }) })).result, 'MANUAL_REVIEW'); // no role
  const nomain = W.classify(mem({ 'package.json': JSON.stringify({ main: 'gone.js', dependencies: { express: '1' } }) }));
  assert.equal(nomain.result, 'CONFIRM_ENTRYPOINT');
  assert.equal(W.classify(src, { architecture: 'two-tier' }).result, 'MANUAL_REVIEW');
});

test('tfvars accept only validated values: protected projects, names, ports, env names', async () => {
  const c = W.classify(await fixture('cloudsentinel-test-python-clean'));
  for (const id of [11, 13, 17]) assert.throws(() => W.buildTfvars(id, c), /protected/);
  assert.throws(() => W.buildTfvars(0, c)); assert.throws(() => W.buildTfvars(42, c, { clusterName: 'prod; rm -rf' }));
  const bad = structuredClone(c); bad.components[0].port = 80; assert.throws(() => W.buildTfvars(42, bad), /port/);
  const bad2 = structuredClone(c); bad2.components[0].secretKeys = ['ok', 'X"; }']; assert.throws(() => W.buildTfvars(42, bad2), /variable name/);
  const bad3 = structuredClone(c); bad3.components[0].name = 'worker'; assert.throws(() => W.buildTfvars(42, bad3));
  const src = mem({ 'requirements.txt': 'flask' }, { 'app.py': 'import os\nos.environ.get("API_TOKEN")\nos.getenv("PORT")\nos.environ.get("lower")\nserve(app, listen="*:80")' });
  assert.equal(W.classify(src).result, 'MANUAL_REVIEW'); // privileged port 80
});

test('generate copies only the fixed templates and writes values only to terraform.tfvars.json', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cs-eks-gen-')); t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const c = W.classify(await fixture('cloudsentinel-test-flask-postgres'));
  const { root, configurationHash } = await W.generate(dir, W.buildTfvars(42, c));
  assert.match(configurationHash, /^[a-f0-9]{64}$/);
  const files = (await fs.readdir(root)).sort();
  assert.deepEqual(files, ['.terraform.lock.hcl', 'main.tf', 'outputs.tf', 'terraform.tfvars.json', 'variables.tf']);
  for (const f of ['main.tf', 'variables.tf', 'outputs.tf']) assert.equal(await fs.readFile(path.join(root, f), 'utf8'), await fs.readFile(path.join(W.REPO_ROOT, 'terraform/templates/eks-project', f), 'utf8'));
  assert.equal((await fs.stat(path.join(root, 'terraform.tfvars.json'))).mode & 0o777, 0o600);
  assert.ok(!(await fs.readFile(path.join(root, 'main.tf'), 'utf8')).includes('APP_GREETING'));
});

// ---- Dockerfile and manifests ------------------------------------------------------------------------------
test('generated Dockerfiles are pinned, non-root and never use latest', async () => {
  for (const name of ['cloudsentinel-test-python-clean', 'cloudsentinel-test-three-tier']) {
    for (const comp of W.classify(await fixture(name)).components) {
      const d = W.generateDockerfile(comp);
      assert.match(d, /^USER 10001:10001$/m); assert.doesNotMatch(d, /:latest|USER root/);
      assert.match(d, /^FROM (python:3\.12\.15-slim-bookworm|node:22\.23\.3-alpine)$/m);
      assert.match(d, new RegExp(`EXPOSE ${comp.port}`));
    }
  }
});

const outputs = (id, name) => ({ repository_url: `229032674007.dkr.ecr.ap-south-1.amazonaws.com/cloudsentinel/p-${id}-${name}`, role_arn: `arn:aws:iam::229032674007:role/cloudsentinel-p${id}-${name}-irsa`, secret_name: `cloudsentinel/p-${id}/${name}`, log_group_name: `/cloudsentinel/projects/${id}/${name}`, service_account: `p${id}-${name}`, namespace: `cloudsentinel-p-${id}` });
const dbOut = { address: 'cloudsentinel-p42-db.abcdefghij12.ap-south-1.rds.amazonaws.com', port: 5432, db_name: 'app', engine: 'postgres', master_user_secret_arn: 'arn:aws:secretsmanager:ap-south-1:229032674007:secret:rds!db-0123abcd-0123-4567-89ab-0123456789ab-AbC123' };

test('EKS manifests satisfy the Kyverno policies and use IRSA, ECR, ESO and an HPA', async () => {
  const c = W.classify(await fixture('cloudsentinel-test-flask-postgres'));
  const m = generateEksManifests({ projectId: 42, component: c.components[0], outputs: outputs(42, 'app'), database: dbOut, tag: 'v1.0.0-abc1234' }).yaml;
  for (const re of [/replicas: 2/, /runAsNonRoot: true/, /allowPrivilegeEscalation: false/, /privileged: false/, /- ALL/, /automountServiceAccountToken: false/,
    /serviceAccountName: p42-app/, /eks\.amazonaws\.com\/role-arn: arn:aws:iam::229032674007:role\/cloudsentinel-p42-app-irsa/,
    /image: 229032674007\.dkr\.ecr\.ap-south-1\.amazonaws\.com\/cloudsentinel\/p-42-app:v1\.0\.0-abc1234/, /imagePullPolicy: IfNotPresent/,
    /limits:\n\s+cpu: "500m"\n\s+memory: "512Mi"/, /owner: project-42/, /kind: HorizontalPodAutoscaler/, /minReplicas: 2/,
    /kind: ExternalSecret/, /key: cloudsentinel\/p-42\/app/, /property: password/, /type: LoadBalancer/, /pod-security\.kubernetes\.io\/enforce: restricted/,
    /mountPath: \/var\/run\/secrets\/cloudsentinel\/p42-app-secrets/, /DB_HOST: "cloudsentinel-p42-db/]) assert.match(m, re);
  assert.doesNotMatch(m, /:latest|password: |DB_PASSWORD: "/);
  assert.throws(() => generateEksManifests({ projectId: 42, component: c.components[0], outputs: outputs(42, 'app'), database: dbOut, tag: 'latest' }), /latest/);
  assert.throws(() => generateEksManifests({ projectId: 42, component: c.components[0], outputs: { ...outputs(42, 'app'), repository_url: 'docker.io/evil/app' }, database: dbOut, tag: 'v1' }), /repository/);
  assert.throws(() => generateK8sManifests('x', 'nginx:1.0', 8080, 'python', 'cloudsentinel-p-42', { target: 'eks', serviceAccountName: 'p42-app' }), /ECR/);
});

test('three-tier backend Service is private; frontend gets BACKEND_URL; Minikube output unchanged', async () => {
  const c = W.classify(await fixture('cloudsentinel-test-three-tier'));
  const by = Object.fromEntries(c.components.map(x => [x.name, x]));
  const back = generateEksManifests({ projectId: 43, component: by.backend, outputs: outputs(43, 'backend'), database: { ...dbOut, address: 'cloudsentinel-p43-db.abcdefghij12.ap-south-1.rds.amazonaws.com' }, tag: 'v1' }).yaml;
  const front = generateEksManifests({ projectId: 43, component: by.frontend, outputs: outputs(43, 'frontend'), tag: 'v1', backendHost: 'p43-backend' }).yaml;
  assert.match(back, /type: ClusterIP/); assert.doesNotMatch(back, /LoadBalancer/);
  assert.match(front, /type: LoadBalancer/); assert.match(front, /BACKEND_URL: "http:\/\/p43-backend\.cloudsentinel-p-43\.svc\.cluster\.local"/);
  assert.doesNotMatch(front, /ExternalSecret/); // no keys, no database for the frontend
  const mk = generateK8sManifests('demo', 'cloudsentinel-p-5:abc', 8080, 'python', 'cloudsentinel-p-5');
  assert.match(mk.deployment, /replicas: 1/); assert.match(mk.deployment, /imagePullPolicy: Never/); assert.match(mk.service, /type: NodePort/); assert.doesNotMatch(mk.deployment, /envFrom/);
});

// ---- plan allowlist ----------------------------------------------------------------------------------------
const OIDC = 'arn:aws:iam::229032674007:oidc-provider/oidc.eks.ap-south-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF';
const tags = id => ({ Project: 'cloudsentinel', ProjectId: String(id), Module: '8-eks-workload', Environment: 'development', ManagedBy: 'Terraform' });
function fakePlan(id, components, db) {
  const rc = [];
  const add = (address, type, after) => rc.push({ address, mode: 'managed', type, change: { actions: ['create'], after } });
  for (const c of components) {
    const m = `module.workload["${c}"]`;
    add(`${m}.aws_ecr_repository.this`, 'aws_ecr_repository', { name: `cloudsentinel/p-${id}-${c}`, image_tag_mutability: 'IMMUTABLE', image_scanning_configuration: [{ scan_on_push: true }], tags_all: tags(id) });
    add(`${m}.aws_secretsmanager_secret.this`, 'aws_secretsmanager_secret', { name: `cloudsentinel/p-${id}/${c}`, recovery_window_in_days: 0, tags_all: tags(id) });
    add(`${m}.aws_cloudwatch_log_group.this`, 'aws_cloudwatch_log_group', { name: `/cloudsentinel/projects/${id}/${c}`, retention_in_days: 7, tags_all: tags(id) });
    add(`${m}.aws_iam_role.irsa`, 'aws_iam_role', { name: `cloudsentinel-p${id}-${c}-irsa`, tags_all: tags(id), permissions_boundary: 'arn:aws:iam::229032674007:policy/cloudsentinel-workload-boundary', assume_role_policy: JSON.stringify({ Version: '2012-10-17', Statement: [{ Sid: 'ServiceAccountOnly', Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity', Principal: { Federated: OIDC }, Condition: { StringEquals: { 'oidc.eks.ap-south-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF:sub': `system:serviceaccount:cloudsentinel-p-${id}:p${id}-${c}`, 'oidc.eks.ap-south-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF:aud': 'sts.amazonaws.com' } } }] }) });
    add(`${m}.aws_iam_role_policy.irsa`, 'aws_iam_role_policy', { name: `cloudsentinel-p${id}-${c}-access`, policy: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'], Resource: `arn:aws:secretsmanager:ap-south-1:229032674007:secret:cloudsentinel/p-${id}/${c}-??????` }, { Effect: 'Allow', Action: ['logs:PutLogEvents', 'logs:CreateLogStream'], Resource: `arn:aws:logs:ap-south-1:229032674007:log-group:/cloudsentinel/projects/${id}/${c}:log-stream:*` }] }) });
  }
  if (db) {
    add('module.database[0].aws_db_subnet_group.this', 'aws_db_subnet_group', { name: `cloudsentinel-p${id}-db`, tags_all: tags(id) });
    add('module.database[0].aws_security_group.this', 'aws_security_group', { name: `cloudsentinel-p${id}-db`, egress: [], ingress: [{ from_port: 5432, to_port: 5432, protocol: 'tcp', cidr_blocks: [], ipv6_cidr_blocks: [], prefix_list_ids: [], self: false, security_groups: ['sg-0123456789abcdef0'] }], tags_all: tags(id) });
    add('module.database[0].aws_db_instance.this', 'aws_db_instance', { identifier: `cloudsentinel-p${id}-db`, engine: 'postgres', instance_class: 'db.t3.micro', publicly_accessible: false, storage_encrypted: true, manage_master_user_password: true, multi_az: false, allocated_storage: 20, tags_all: tags(id) });
  }
  rc.push({ address: 'data.aws_eks_cluster.shared', mode: 'data', type: 'aws_eks_cluster', change: { actions: ['read'] } });
  return { format_version: '1.2', resource_changes: rc, configuration: { provider_config: { aws: { expressions: { region: { constant_value: 'ap-south-1' }, allowed_account_ids: { constant_value: ['229032674007'] } } } } } };
}
const two = { projectId: 42, components: ['app'], database: 'postgres' };

test('allowlist accepts exactly the generated resources (one-, two- and three-tier)', () => {
  assert.equal(W.inspectPlan(fakePlan(42, ['app'], false), { projectId: 42, components: ['app'], database: null }).length, 5);
  assert.equal(W.inspectPlan(fakePlan(42, ['app'], true), two).length, 8);
  assert.equal(W.inspectPlan(fakePlan(43, ['frontend', 'backend'], true), { projectId: 43, components: ['frontend', 'backend'], database: 'postgres' }).length, 13);
});

test('allowlist rejects public RDS, open database access, extra types, missing tags, wrong account and admin IAM', () => {
  const cases = {
    PUBLIC_RDS: p => { p.resource_changes.find(r => r.type === 'aws_db_instance').change.after.publicly_accessible = true; },
    DATABASE_OPEN_TO_NETWORK: p => { p.resource_changes.find(r => r.type === 'aws_security_group').change.after.ingress[0].cidr_blocks = ['0.0.0.0/0']; },
    UNEXPECTED_RESOURCE: p => { p.resource_changes.push({ address: 'aws_instance.x', mode: 'managed', type: 'aws_instance', change: { actions: ['create'], after: {} } }); },
    'UNEXPECTED_RESOURCE aws_iam_role_policy_attachment': p => { p.resource_changes.push({ address: 'module.workload["app"].aws_iam_role_policy_attachment.admin', mode: 'managed', type: 'aws_iam_role_policy_attachment', change: { actions: ['create'], after: { policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess' } } }); },
    TAGS_MISSING_OR_WRONG: p => { delete p.resource_changes[0].change.after.tags_all.Project; },
    'TAGS_MISSING_OR_WRONG ': p => { p.resource_changes[1].change.after.tags_all.ProjectId = '13'; },
    ACCOUNT_OR_REGION_NOT_PINNED: p => { p.configuration.provider_config.aws.expressions.allowed_account_ids.constant_value = ['000000000000']; },
    'ACCOUNT_OR_REGION_NOT_PINNED ': p => { p.configuration.provider_config.aws.expressions.region.constant_value = 'us-east-1'; },
    NON_CREATE_ACTION: p => { p.resource_changes[0].change.actions = ['delete', 'create']; },
    IAM_ACTION_NOT_ALLOWED: p => { const r = p.resource_changes.find(x => x.type === 'aws_iam_role_policy'); r.change.after.policy = JSON.stringify({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }); },
    IAM_RESOURCE_NOT_ALLOWED: p => { const r = p.resource_changes.find(x => x.type === 'aws_iam_role_policy'); r.change.after.policy = JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: 'arn:aws:secretsmanager:ap-south-1:229032674007:secret:cloudsentinel/p-13/app-??????' }] }); },
    IAM_TRUST: p => { const r = p.resource_changes.find(x => x.type === 'aws_iam_role'); r.change.after.assume_role_policy = JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: '*' } }] }); },
    IAM_PERMISSIONS_BOUNDARY: p => { delete p.resource_changes.find(x => x.type === 'aws_iam_role').change.after.permissions_boundary; },
    IAM_ROLE_POLICIES: p => { p.resource_changes.find(x => x.type === 'aws_iam_role').change.after.managed_policy_arns = ['arn:aws:iam::aws:policy/AdministratorAccess']; },
    RDS_SETTINGS: p => { p.resource_changes.find(r => r.type === 'aws_db_instance').change.after.storage_encrypted = false; },
    'RDS_SETTINGS ': p => { const a = p.resource_changes.find(r => r.type === 'aws_db_instance').change.after; a.manage_master_user_password = false; a.password = 'x'; },
    RDS_IDENTITY: p => { p.resource_changes.find(r => r.type === 'aws_db_instance').change.after.instance_class = 'db.r6g.large'; },
    SG_EGRESS: p => { p.resource_changes.find(r => r.type === 'aws_security_group').change.after.egress = [{ cidr_blocks: ['0.0.0.0/0'] }]; },
    RESOURCE_COUNT_MISMATCH: p => { p.resource_changes.splice(0, 1); },
    SECRET_SETTINGS: p => { p.resource_changes.find(r => r.type === 'aws_secretsmanager_secret').change.after.name = 'other/secret'; },
    ECR_SETTINGS: p => { p.resource_changes.find(r => r.type === 'aws_ecr_repository').change.after.image_tag_mutability = 'MUTABLE'; },
  };
  for (const [code, mutate] of Object.entries(cases)) {
    const p = fakePlan(42, ['app'], true); mutate(p);
    assert.throws(() => W.inspectPlan(p, two), e => e.message.includes(code.trim()), code);
  }
  assert.throws(() => W.inspectPlan(fakePlan(13, ['app'], true), { ...two, projectId: 13 }), /protected/);
  assert.throws(() => W.inspectPlan(fakePlan(42, ['app'], true), { projectId: 42, components: ['app'], database: null }), /UNEXPECTED_RESOURCE/);
  assert.throws(() => W.inspectPlan({ errored: true }, two), /MALFORMED/);
});

test('destroy plans may delete only the applied addresses', () => {
  const addresses = W.inspectPlan(fakePlan(42, ['app'], true), two).map(r => r.address);
  const destroy = () => ({ resource_changes: addresses.map(a => ({ address: a, mode: 'managed', type: 'x', change: { actions: ['delete'] } })) });
  assert.equal(W.inspectDestroyPlan(destroy(), { projectId: 42, addresses }).length, 8);
  const extra = destroy(); extra.resource_changes.push({ address: 'module.other.aws_vpc.x', mode: 'managed', type: 'aws_vpc', change: { actions: ['delete'] } });
  assert.throws(() => W.inspectDestroyPlan(extra, { projectId: 42, addresses }), /OUT_OF_SCOPE/);
  const create = destroy(); create.resource_changes[0].change.actions = ['create'];
  assert.throws(() => W.inspectDestroyPlan(create, { projectId: 42, addresses }), /NON_DELETE/);
  const partial = destroy(); partial.resource_changes.pop();
  assert.throws(() => W.inspectDestroyPlan(partial, { projectId: 42, addresses }), /SCOPE_MISMATCH/);
});

// ---- gated lifecycle (fake tools, no cloud calls) --------------------------------------------------------------
function fakeTools(id, calls) {
  return async (exe, args, { cwd }) => {
    calls.push([path.basename(exe), args[0]]);
    if (args[0] === 'configure') return { code: 0, stdout: JSON.stringify({ AccessKeyId: 'ASIATESTTESTTESTTEST', SecretAccessKey: 'test-only', SessionToken: 'test-only-token', Expiration: new Date(Date.now() + 3600e3).toISOString() }), stderr: '' };
    if (args[0] === 'sts') return { code: 0, stdout: JSON.stringify({ Account: '229032674007' }), stderr: '' };
    if (args[0] === 'plan') { const out = args.find(a => a.startsWith('-out=')).slice(5); await fs.writeFile(path.join(cwd, out), `plan-${Date.now()}-${args.includes('-destroy')}`); return { code: 0, stdout: '', stderr: '' }; }
    if (args[0] === 'show') {
      if (args[2] === 'destroy.tfplan') { const p = fakePlan(id, ['app'], true); return { code: 0, stdout: JSON.stringify({ resource_changes: p.resource_changes.filter(r => r.mode === 'managed').map(r => ({ ...r, change: { actions: ['delete'] } })) }), stderr: '' }; }
      return { code: 0, stdout: JSON.stringify(fakePlan(id, ['app'], true)), stderr: '' };
    }
    if (args[0] === 'apply') { await fs.mkdir(path.dirname(path.join(cwd, 'x')), { recursive: true }); return { code: 0, stdout: 'Apply complete', stderr: '' }; }
    if (args[0] === 'output') return { code: 0, stdout: JSON.stringify({ components: { value: { app: outputs(id, 'app') } }, database: { value: dbOut } }), stderr: '' };
    if (path.basename(exe) === 'trivy') return { code: 0, stdout: JSON.stringify({ Results: [{ Target: 'terraform/modules/project-workload/main.tf' }, { Target: 'terraform/modules/project-database/main.tf' }] }), stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
}
async function engine(t, calls) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cs-eks-engine-')); t.after(() => fs.rm(root, { recursive: true, force: true }));
  const backupDir = path.join(root, 'backup');
  const e = new WorkloadInfrastructure({ root: path.join(root, 'eks'), source: () => W.localSource(path.join(FIX, 'cloudsentinel-test-flask-postgres')), run: fakeTools(42, calls), backupDir });
  // the fake apply does not write state; give it one so the backup step has something to copy
  const origStep = e.step.bind(e);
  e.step = async (logs, name, args, o) => { const r = await origStep(logs, name, args, o); if (name === 'apply' || name === 'destroy') { const sd = path.join(e.root, '42', 'state'); await fs.writeFile(path.join(sd, 'terraform.tfstate'), '{}'); } return r; };
  return e;
}

test('apply is refused unless INFRA_APPLY_ENABLED=true and the kill switch is off', async t => {
  const old = { ...process.env }; t.after(() => { process.env = old; });
  delete process.env.INFRA_APPLY_ENABLED; delete process.env.INFRA_KILL_SWITCH;
  const calls = [], e = await engine(t, calls), project = { id: 42 };
  assert.equal(applyGate(e.root).enabled, false);
  await assert.rejects(e.apply(project, 'u1'), /Real apply is disabled: INFRA_APPLY_ENABLED is not true/);
  process.env.INFRA_APPLY_ENABLED = 'true'; process.env.INFRA_KILL_SWITCH = 'on';
  await assert.rejects(e.apply(project, 'u1'), /Kill switch/);
  delete process.env.INFRA_KILL_SWITCH; await fs.mkdir(e.root, { recursive: true }); await fs.writeFile(path.join(e.root, 'KILL_SWITCH'), '');
  await assert.rejects(e.apply(project, 'u1'), /Kill switch file/);
  assert.equal(calls.filter(c => c[1] === 'apply').length, 0);
  for (const id of [11, 13, 17]) await assert.rejects(e.analyze({ id }, 'u1'), /protected/);
});

test('full lifecycle: plan hash approval is single use, apply backs up state, destroy is scoped', async t => {
  const old = { ...process.env }; t.after(() => { process.env = old; });
  process.env.INFRA_APPLY_ENABLED = 'true'; delete process.env.INFRA_KILL_SWITCH;
  const calls = [], e = await engine(t, calls), project = { id: 42 };
  let r = await e.analyze(project, 'u1'); assert.equal(r.status, 'ANALYZED');
  await assert.rejects(e.plan(project, 'u1'), /Confirm the architecture/);
  r = await e.confirm(project, 'u1', { architecture: 'two-tier' }); assert.equal(r.status, 'CONFIRMED');
  await assert.rejects(e.apply(project, 'u1'), /Nothing to apply/);
  r = await e.plan(project, 'u1'); assert.equal(r.status, 'AWAITING_APPROVAL'); assert.equal(r.plan.summary.length, 8);
  assert.deepEqual(calls.filter(c => c[0] === 'terraform').map(c => c[1]), ['fmt', 'init', 'validate', 'plan', 'show']);
  assert.ok(calls.some(c => c[0] === 'trivy'));
  assert.equal(e.publicRecord(r).job, undefined);
  await assert.rejects(e.apply(project, 'u1'), /Approval missing/);
  await assert.rejects(e.approve(project, 'u1', { hash: 'f'.repeat(64) }), /checksum mismatch/);
  r = await e.approve(project, 'u1', { hash: r.plan.hash });
  await assert.rejects(e.approve(project, 'u1', { hash: r.plan.hash }), /already recorded/);
  await assert.rejects(e.apply(project, 'u2'), /another user/);
  r = await e.apply(project, 'u1'); assert.equal(r.status, 'APPLIED'); assert.equal(r.applied.addresses.length, 8);
  assert.equal(calls.filter(c => c[1] === 'apply').length, 1);
  await assert.rejects(e.apply(project, 'u1'), /Nothing to apply/); // approval consumed; no replay
  assert.equal((await fs.readdir(path.join(e.backupDir, '42'))).length, 1);
  const art = await e.artifacts(project, { tag: 'v1.0.0' }); assert.match(art[0].dockerfile, /USER 10001/); assert.match(art[0].manifests.yaml, /p-42-app:v1\.0\.0/);
  r = await e.destroyPlan(project, 'u1'); assert.equal(r.status, 'AWAITING_DESTROY_APPROVAL'); assert.equal(r.destroyPlan.summary.length, 8);
  await assert.rejects(e.destroy(project, 'u1'), /Approval missing/);
  r = await e.approve(project, 'u1', { hash: r.destroyPlan.hash, kind: 'destroy' });
  r = await e.destroy(project, 'u1'); assert.equal(r.status, 'DESTROYED');
  const audit = (await fs.readFile(path.join(e.root, '42', 'audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse).map(a => a.action);
  assert.deepEqual(audit.filter(a => !a.endsWith('-failed')), ['analyze', 'confirm', 'plan', 'approve-apply', 'apply-start', 'apply-done', 'destroy-plan', 'approve-destroy', 'destroy-start', 'destroy-done']);
  const stored = await fs.readFile(path.join(e.root, '42', 'metadata.json'), 'utf8');
  assert.ok(!stored.includes('test-only') && !stored.includes('ASIATEST'), 'credentials never stored');
});

test('a Trivy run that did not evaluate the modules refuses the plan', async t => {
  const calls = [], root = await fs.mkdtemp(path.join(os.tmpdir(), 'cs-eks-trivy-')); t.after(() => fs.rm(root, { recursive: true, force: true }));
  const base = fakeTools(42, calls);
  const run = async (exe, args, o) => (path.basename(exe) === 'trivy' ? { code: 0, stdout: '{"Results":[{"Target":"terraform/templates/eks-project"}]}', stderr: '' } : base(exe, args, o));
  const e = new WorkloadInfrastructure({ root: path.join(root, 'eks'), source: () => W.localSource(path.join(FIX, 'cloudsentinel-test-flask-postgres')), run, backupDir: '' });
  await e.analyze({ id: 42 }, 'u'); await e.confirm({ id: 42 }, 'u', { architecture: 'two-tier' });
  await assert.rejects(e.plan({ id: 42 }, 'u'), /did not evaluate the workload module/);
  assert.equal(calls.filter(c => c[1] === 'plan').length, 0);
});

test('a tampered plan file after approval is rejected before apply', async t => {
  const old = { ...process.env }; t.after(() => { process.env = old; });
  process.env.INFRA_APPLY_ENABLED = 'true';
  const calls = [], e = await engine(t, calls), project = { id: 42 };
  await e.analyze(project, 'u1'); await e.confirm(project, 'u1', { architecture: 'two-tier' });
  let r = await e.plan(project, 'u1'); r = await e.approve(project, 'u1', { hash: r.plan.hash });
  const file = path.join((await e.get(42)).job.root, 'project.tfplan');
  await fs.chmod(file, 0o600); await fs.writeFile(file, 'tampered');
  await assert.rejects(e.apply(project, 'u1'), /changed after approval/);
  assert.equal(calls.filter(c => c[1] === 'apply').length, 0);
});

test('expired AWS login is reported with the aws login command and nothing runs', async t => {
  const calls = [];
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cs-eks-exp-')); t.after(() => fs.rm(root, { recursive: true, force: true }));
  const run = async (exe, args, o) => (args[0] === 'configure' ? { code: 255, stdout: '', stderr: 'Error: login session has expired' } : fakeTools(42, calls)(exe, args, o));
  const e = new WorkloadInfrastructure({ root: path.join(root, 'eks'), source: () => W.localSource(path.join(FIX, 'cloudsentinel-test-flask-postgres')), run, backupDir: '' });
  await e.analyze({ id: 42 }, 'u'); await e.confirm({ id: 42 }, 'u', { architecture: 'two-tier' });
  await assert.rejects(e.plan({ id: 42 }, 'u'), /aws login --profile cloudsentinel-dev/);
  assert.equal(calls.filter(c => c[1] === 'plan').length, 0);
});

test('env-var and port detection read names only', () => {
  assert.deepEqual([...W.envNamesFrom('os.environ.get("A_B") os.getenv(\'C\') os.environ["D"] process.env.E process.env["F"] os.environ.get(x)')].sort(), ['A_B', 'C', 'D', 'E', 'F']);
  assert.equal(W.portFrom('serve(app, listen="*:8080")'), 8080);
  assert.equal(W.portFrom('app.listen(process.env.PORT || 3001)'), 3001);
  assert.equal(W.portFrom('nothing here'), null);
  const sha = crypto.createHash('sha256').update('x').digest('hex'); assert.equal(sha.length, 64);
});
