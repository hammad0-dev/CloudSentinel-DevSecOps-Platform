'use strict';
// CloudSentinel - gated lifecycle for per-project EKS workload infrastructure (Module 8).
//
//   analyze -> confirm (architecture, uncertain entrypoints) -> plan (generate, fmt, init, validate, Trivy, plan,
//   allowlist) -> approve (exact plan SHA-256, single use) -> apply (gated) -> destroy-plan -> approve -> destroy
//
// Apply and destroy run only when ALL of these hold:
//   - INFRA_APPLY_ENABLED=true
//   - the kill switch is off (INFRA_KILL_SWITCH is not "on" and <artifact root>/KILL_SWITCH does not exist)
//   - the project is not protected (11, 13, 17)
//   - an unconsumed, unexpired approval exists for exactly this plan file's SHA-256 (consumed before apply runs)
//   - the plan passed the resource allowlist (inspectPlan / inspectDestroyPlan)
//   - the AWS identity is account 229032674007 and the region ap-south-1
// State is one local file per project (<artifact root>/eks-workloads/<id>/state/terraform.tfstate), copied to
// INFRA_STATE_BACKUP_DIR after every apply/destroy. Every step is appended to <...>/<id>/audit.jsonl.
// Credentials: Terraform and the AWS CLI run with AWS_PROFILE=$INFRA_AWS_PROFILE so the SDK refreshes short-lived
// `aws login` credentials during long applies; `aws configure export-credentials` is used only to pre-check expiry
// and identity and to redact the keys from stored tool output.

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const W = require('./eksWorkload');
const { Planner } = require('./infrastructurePlanning');
const { command, redact } = require('./terraformPlanRunner');

const TOOLS = {
  terraform: process.env.INFRA_TERRAFORM_BIN || '/usr/bin/terraform',
  aws: process.env.INFRA_AWS_BIN || '/home/hammad/.local/bin/aws',
  trivy: process.env.INFRA_TRIVY_BIN || '/snap/bin/trivy',
};
const PLAN_TTL_MS = 30 * 60 * 1000, APPROVAL_TTL_MS = 15 * 60 * 1000;
const fail = (message, status = 409) => Object.assign(new Error(message), { safe: true, status });
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const now = () => new Date().toISOString();

function applyGate(root) {
  const reasons = [];
  if (process.env.INFRA_APPLY_ENABLED !== 'true') reasons.push('INFRA_APPLY_ENABLED is not true');
  if (process.env.INFRA_KILL_SWITCH === 'on') reasons.push('Kill switch INFRA_KILL_SWITCH=on');
  try { require('node:fs').accessSync(path.join(root, 'KILL_SWITCH')); reasons.push('Kill switch file present'); } catch { /* absent */ }
  return { enabled: reasons.length === 0, reasons };
}

class WorkloadInfrastructure {
  constructor({
    root = path.join(process.env.INFRA_ARTIFACT_ROOT || path.join(os.homedir(), '.cloudsentinel', 'infrastructure'), 'eks-workloads'),
    source, run = command, profile = process.env.INFRA_AWS_PROFILE || 'cloudsentinel-dev',
    backupDir = process.env.INFRA_STATE_BACKUP_DIR || '/mnt/d/ml-backup/eks-state',
    pluginCache = process.env.INFRA_TF_PLUGIN_CACHE_DIR || '', trivyCache = process.env.INFRA_TRIVY_CACHE_DIR || '',
    clusterName = process.env.EKS_CLUSTER_NAME || W.DEFAULT_CLUSTER, repoRoot = W.REPO_ROOT,
  } = {}) {
    if (typeof source !== 'function') throw new Error('A repository source is required');
    Object.assign(this, { root, source, run, profile, backupDir, pluginCache, trivyCache, clusterName, repoRoot });
    this.store = new Planner({ root, source, discovery: async () => ({}) });
  }

  gate() { return applyGate(this.root); }
  async audit(dir, entry) { await fs.appendFile(path.join(dir, 'audit.jsonl'), JSON.stringify({ at: now(), ...entry }) + '\n', { mode: 0o600 }); }
  async get(id) { return this.store.get(id); }
  async save(dir, data) { data.updatedAt = now(); data.history = [...(data.history || []).slice(-29), { status: data.status, at: data.updatedAt }]; await this.store.save(dir, data); return data; }

  publicRecord(data) {
    const { job, ...safe } = data;
    const gate = this.gate();
    return { ...safe, applyEnabled: gate.enabled, applyBlockers: gate.reasons, account: W.ACCOUNT, region: W.REGION };
  }

  // ---- analyze / confirm ------------------------------------------------------------------------------------
  async analyze(project, userId) {
    W.assertProject(project.id);
    return this.store.locked(project.id, async dir => {
      const source = await this.source(project);
      const classification = W.classify(source);
      const previous = await this.get(project.id);
      if (['APPLYING', 'APPLIED', 'DESTROYING', 'AWAITING_DESTROY_APPROVAL', 'NEEDS_OPERATOR_REVIEW'].includes(previous.status)) throw fail(`Project infrastructure is ${previous.status}; destroy or review it first`);
      const data = { projectId: project.id, status: 'ANALYZED', commit: source.commit, classification, history: previous.history || [] };
      await this.audit(dir, { action: 'analyze', userId, result: classification.result, architecture: classification.architecture, commit: source.commit });
      return this.save(dir, data);
    });
  }

  async confirm(project, userId, input = {}) {
    W.assertProject(project.id);
    const keys = Object.keys(input || {});
    if (keys.some(k => !['architecture', 'entrypoints'].includes(k))) throw fail('Unsupported confirmation field', 400);
    return this.store.locked(project.id, async dir => {
      const data = await this.get(project.id);
      if (!['ANALYZED', 'CONFIRMED', 'MANUAL_REVIEW'].includes(data.status)) throw fail('Analyze the repository first');
      const source = await this.source(project);
      if (source.commit !== data.commit) throw fail('Repository changed; analyze again');
      const entrypoints = input.entrypoints && typeof input.entrypoints === 'object' ? input.entrypoints : {};
      const classification = W.classify(source, { architecture: input.architecture, entrypoints });
      data.classification = classification;
      data.confirmation = { userId, architecture: input.architecture, entrypoints, at: now() };
      data.status = classification.result === 'CONTAINER' ? 'CONFIRMED' : classification.result === 'STATIC_SITE' ? 'STATIC_SITE' : classification.result === 'CONFIRM_ENTRYPOINT' ? 'ANALYZED' : 'MANUAL_REVIEW';
      await this.audit(dir, { action: 'confirm', userId, result: data.status, architecture: input.architecture });
      return this.save(dir, data);
    });
  }

  // ---- credentials and tools ----------------------------------------------------------------------------------
  baseEnv() {
    const env = { PATH: '/usr/bin:/bin:/snap/bin', HOME: process.env.HOME, LANG: 'C.UTF-8', TF_IN_AUTOMATION: 'true', TF_INPUT: '0',
      AWS_REGION: W.REGION, AWS_DEFAULT_REGION: W.REGION, AWS_EC2_METADATA_DISABLED: 'true', AWS_PAGER: '', CHECKPOINT_DISABLE: '1' };
    if (this.pluginCache) env.TF_PLUGIN_CACHE_DIR = this.pluginCache;
    return env;
  }
  async credentials(env, cwd) {
    const r = await this.run(TOOLS.aws, ['configure', 'export-credentials', '--profile', this.profile, '--format', 'process'], { env: this.baseEnv(), cwd, timeout: 20000 });
    if (r.code !== 0) {
      const expired = /expired|login|sso/i.test(r.stderr || '');
      throw fail(expired ? `AWS login session for profile ${this.profile} has expired; run: aws login --profile ${this.profile}` : `AWS credentials for profile ${this.profile} unavailable`);
    }
    let c; try { c = JSON.parse(r.stdout); } catch { throw fail('AWS credentials unavailable'); }
    if (!c.AccessKeyId || !c.SecretAccessKey) throw fail('AWS credentials unavailable');
    if (c.Expiration && Date.parse(c.Expiration) <= Date.now() + 5 * 60 * 1000) throw fail(`AWS credentials for ${this.profile} expire within 5 minutes; run: aws login --profile ${this.profile}`);
    // Child processes get the PROFILE, not the exported keys: `aws login` credentials last about 15 minutes and only
    // the SDK's profile provider refreshes them, so static keys expired in the middle of a 10-minute RDS create.
    // The exported keys are used only for the checks above and to redact any accidental echo in tool output.
    Object.assign(env, { AWS_PROFILE: this.profile });
    for (const k of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']) delete env[k];
    const secrets = [c.AccessKeyId, c.SecretAccessKey, c.SessionToken].filter(Boolean);
    const id = await this.run(TOOLS.aws, ['sts', 'get-caller-identity', '--output', 'json'], { env, cwd, timeout: 20000 });
    let account; try { account = JSON.parse(id.stdout).Account; } catch { /* below */ }
    if (id.code !== 0 || account !== W.ACCOUNT) throw fail('AWS identity is not account 229032674007');
    return secrets;
  }
  async step(logs, name, args, { cwd, env, secrets = [], timeout = 300000, exe = TOOLS.terraform, allowCodes = [0] }) {
    const r = await this.run(exe, args, { cwd, env, timeout, limit: 32 * 1024 * 1024 });
    logs.push({ step: name, code: r.code, stdout: name === 'show' || name === 'output' ? '[WITHHELD]' : redact(r.stdout, secrets), stderr: redact(r.stderr, secrets) });
    if (!allowCodes.includes(r.code)) {
      // apply/destroy can fail part-way: some resources may exist (they are in the saved state). Never say otherwise.
      throw fail(['apply', 'destroy'].includes(name)
        ? `Terraform ${name} failed part-way; resources may have changed (see state); operator review required`
        : `Terraform ${name} failed; nothing applied`);
    }
    return r;
  }
  async writeLog(dir, name, logs) { await fs.writeFile(path.join(dir, `${name}-${Date.now()}.log.json`), JSON.stringify(logs, null, 1), { mode: 0o600 }); }

  // ---- plan ---------------------------------------------------------------------------------------------------
  async plan(project, userId) {
    W.assertProject(project.id);
    return this.store.locked(project.id, async dir => {
      const data = await this.get(project.id);
      if (data.status !== 'CONFIRMED') throw fail('Confirm the architecture (and any uncertain entrypoint) before planning');
      const source = await this.source(project);
      if (source.commit !== data.commit) throw fail('Repository changed; analyze again');
      const tfvars = W.buildTfvars(project.id, data.classification, { clusterName: this.clusterName });
      const job = await fs.mkdtemp(path.join(dir, 'plan-'));
      await fs.chmod(job, 0o700);
      const stateDir = path.join(dir, 'state');
      await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
      const { root, configurationHash } = await W.generate(job, tfvars, { repoRoot: this.repoRoot });
      const env = this.baseEnv(), logs = [];
      let secrets = [];
      try {
        await this.step(logs, 'fmt', ['fmt', '-check', '-recursive', job], { cwd: root, env });
        // IaC scan of the generated folder before init (so .terraform/ is not walked); any CRITICAL finding stops here.
        // --tf-vars is required: without it Trivy cannot expand the for_each/count modules and silently checks nothing.
        const trivyArgs = ['config', '--quiet', '--format', 'json', '--severity', 'CRITICAL', '--exit-code', '1', '--tf-vars', path.join(root, 'terraform.tfvars.json'), ...(this.trivyCache ? ['--cache-dir', this.trivyCache] : []), job];
        const scan = await this.step(logs, 'trivy', trivyArgs, { cwd: root, env, exe: TOOLS.trivy, timeout: 180000 });
        let targets = [];
        try { targets = (JSON.parse(scan.stdout || '{}').Results || []).map(r => r.Target); } catch { /* checked below */ }
        if (process.env.EKS_TRIVY_REQUIRE_MODULES !== 'false' && !targets.some(t => t.endsWith('project-workload/main.tf'))) throw fail('IaC scan did not evaluate the workload module; plan refused');
        await this.step(logs, 'init', ['init', '-input=false', '-no-color', '-lockfile=readonly', `-backend-config=path=${path.join(stateDir, 'terraform.tfstate')}`], { cwd: root, env });
        await this.step(logs, 'validate', ['validate', '-no-color'], { cwd: root, env });
        secrets = await this.credentials(env, root);
        await this.step(logs, 'plan', ['plan', '-input=false', '-no-color', '-lock=true', '-out=project.tfplan'], { cwd: root, env, secrets });
        const shown = await this.step(logs, 'show', ['show', '-json', 'project.tfplan'], { cwd: root, env, secrets });
        const expected = { projectId: project.id, components: Object.keys(tfvars.components), database: tfvars.database.engine === 'none' ? null : tfvars.database.engine };
        const summary = W.inspectPlan(JSON.parse(shown.stdout), expected);
        const file = path.join(root, 'project.tfplan');
        await fs.chmod(file, 0o400);
        const hash = sha256(await fs.readFile(file));
        data.status = 'AWAITING_APPROVAL';
        data.job = { dir: job, root, stateDir };
        data.plan = { kind: 'apply', hash, configurationHash, expected, summary, createdAt: now(), expiresAt: new Date(Date.now() + PLAN_TTL_MS).toISOString(), stateKey: `projects/${project.id}/eks/terraform.tfstate` };
        delete data.approval; delete data.destroyPlan;
        await this.audit(dir, { action: 'plan', userId, result: 'AWAITING_APPROVAL', planHash: hash, resources: summary.length });
        return this.save(dir, data);
      } catch (e) {
        await this.audit(dir, { action: 'plan', userId, result: 'REJECTED', error: e.safe ? e.message : 'Planning failed' });
        throw e.safe ? e : fail('Planning failed; nothing applied');
      } finally {
        for (const k of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']) delete env[k];
        await this.writeLog(job, 'plan', logs).catch(() => {});
      }
    });
  }

  // ---- approval (single use, exact hash) ----------------------------------------------------------------------
  async approve(project, userId, { hash, kind = 'apply' } = {}) {
    W.assertProject(project.id);
    return this.store.locked(project.id, async dir => {
      const data = await this.get(project.id);
      const plan = kind === 'destroy' ? data.destroyPlan : data.plan;
      const wanted = kind === 'destroy' ? 'AWAITING_DESTROY_APPROVAL' : 'AWAITING_APPROVAL';
      if (data.status !== wanted || !plan) throw fail('No plan awaiting approval');
      if (data.approval && data.approval.kind === kind && data.approval.hash === plan.hash) throw fail('Plan approval already recorded; a new plan is required for another approval');
      if (Date.parse(plan.expiresAt) <= Date.now()) throw fail('Plan expired; plan again');
      if (typeof hash !== 'string' || hash !== plan.hash) throw fail('Plan checksum mismatch');
      if (sha256(await fs.readFile(path.join(data.job.root, plan.file || (kind === 'destroy' ? 'destroy.tfplan' : 'project.tfplan')))) !== plan.hash) throw fail('Plan file changed after review');
      data.approval = { kind, hash, userId, at: now(), expiresAt: new Date(Math.min(Date.parse(plan.expiresAt), Date.now() + APPROVAL_TTL_MS)).toISOString(), consumedAt: null };
      await this.audit(dir, { action: `approve-${kind}`, userId, planHash: hash });
      return this.save(dir, data);
    });
  }

  async consume(dir, data, kind, userId) {
    const plan = kind === 'destroy' ? data.destroyPlan : data.plan;
    const a = data.approval;
    if (!a || a.kind !== kind || a.consumedAt || a.hash !== plan?.hash || Date.parse(a.expiresAt) <= Date.now()) throw fail('Approval missing, expired, already used or for another plan');
    if (a.userId !== userId) throw fail('Approval belongs to another user');
    const file = path.join(data.job.root, kind === 'destroy' ? 'destroy.tfplan' : 'project.tfplan');
    if (sha256(await fs.readFile(file)) !== a.hash) throw fail('Plan file changed after approval');
    a.consumedAt = now();
    data.status = kind === 'destroy' ? 'DESTROYING' : 'APPLYING';
    await this.save(dir, data); // consumed before Terraform runs: an approval can never be replayed
    return file;
  }

  async backupState(projectId, stateDir, label) {
    if (!this.backupDir) return null;
    const target = path.join(this.backupDir, String(projectId));
    await fs.mkdir(target, { recursive: true, mode: 0o700 });
    const file = path.join(target, `terraform.tfstate.${label}.${new Date().toISOString().replace(/[:.]/g, '-')}`);
    await fs.copyFile(path.join(stateDir, 'terraform.tfstate'), file);
    await fs.chmod(file, 0o600).catch(() => {});
    return file;
  }

  async applyOrDestroy(project, userId, kind) {
    W.assertProject(project.id);
    const gate = this.gate();
    if (!gate.enabled) { const e = fail(`Real apply is disabled: ${gate.reasons.join('; ')}`); throw e; }
    return this.store.locked(project.id, async dir => {
      const data = await this.get(project.id);
      const wanted = kind === 'destroy' ? 'AWAITING_DESTROY_APPROVAL' : 'AWAITING_APPROVAL';
      if (data.status !== wanted) throw fail(`Nothing to ${kind}`);
      const env = this.baseEnv(), logs = [];
      const secrets = await this.credentials(env, data.job.root);
      if (!this.gate().enabled) throw fail('Kill switch engaged; nothing applied'); // re-check right before consuming
      const file = await this.consume(dir, data, kind, userId);
      await this.audit(dir, { action: `${kind}-start`, userId, planHash: data.approval.hash });
      try {
        await this.step(logs, kind, ['apply', '-input=false', '-no-color', '-lock=true', path.basename(file)], { cwd: data.job.root, env, secrets, timeout: 45 * 60 * 1000 });
        const backup = await this.backupState(project.id, data.job.stateDir, kind).catch(() => null);
        if (kind === 'apply') {
          const out = await this.step(logs, 'output', ['output', '-json', '-no-color'], { cwd: data.job.root, env, secrets });
          const o = JSON.parse(out.stdout);
          data.outputs = { components: o.components?.value || {}, database: o.database?.value || null };
          data.applied = { addresses: data.plan.summary.map(r => r.address), at: now(), planHash: data.approval.hash, stateBackup: backup ? path.basename(backup) : null };
          data.status = 'APPLIED';
        } else {
          data.status = 'DESTROYED';
          data.destroyed = { at: now(), planHash: data.approval.hash, stateBackup: backup ? path.basename(backup) : null, recovery: Boolean(data.recovery) };
          delete data.outputs;
          delete data.recovery;
        }
        await this.audit(dir, { action: `${kind}-done`, userId, result: data.status });
        return this.save(dir, data);
      } catch (e) {
        data.status = 'NEEDS_OPERATOR_REVIEW';
        data.blockers = [`${kind} outcome uncertain; inspect state ${data.plan?.stateKey}; no retry was attempted`];
        await this.backupState(project.id, data.job.stateDir, `${kind}-failed`).catch(() => null);
        await this.audit(dir, { action: `${kind}-failed`, userId, error: e.safe ? e.message : 'Terraform failed' });
        await this.save(dir, data);
        throw fail(`${kind} failed; operator review required (no retry)`);
      } finally {
        for (const k of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']) delete env[k];
        await this.writeLog(data.job.dir, kind, logs).catch(() => {});
      }
    });
  }
  apply(project, userId) { return this.applyOrDestroy(project, userId, 'apply'); }
  destroy(project, userId) { return this.applyOrDestroy(project, userId, 'destroy'); }

  async destroyPlan(project, userId) {
    W.assertProject(project.id);
    return this.store.locked(project.id, async dir => {
      const data = await this.get(project.id);
      // Recovery after a failed apply (NEEDS_OPERATOR_REVIEW): the only way forward is a scoped destroy of what the
      // failed apply created: resources that are in the saved state AND in the approved plan, nothing else.
      const recovering = data.status === 'NEEDS_OPERATOR_REVIEW' || (data.status === 'AWAITING_DESTROY_APPROVAL' && data.recovery);
      if (!recovering && (!['APPLIED', 'AWAITING_DESTROY_APPROVAL'].includes(data.status) || !data.applied)) throw fail('Only applied project infrastructure can be destroyed through this path');
      let addresses = data.applied?.addresses;
      if (recovering) {
        if (!data.job?.stateDir || !data.plan?.summary) throw fail('No saved state or approved plan to recover from; manual review required');
        const state = JSON.parse(await fs.readFile(path.join(data.job.stateDir, 'terraform.tfstate'), 'utf8'));
        addresses = W.recoveryAddresses(state, data.plan.summary.map(r => r.address));
        data.recovery = { addresses, at: now() };
      }
      const env = this.baseEnv(), logs = [];
      try {
        const secrets = await this.credentials(env, data.job.root);
        await this.step(logs, 'destroy-plan', ['plan', '-destroy', '-input=false', '-no-color', '-lock=true', '-out=destroy.tfplan'], { cwd: data.job.root, env, secrets });
        const shown = await this.step(logs, 'show', ['show', '-json', 'destroy.tfplan'], { cwd: data.job.root, env, secrets });
        const summary = W.inspectDestroyPlan(JSON.parse(shown.stdout), { projectId: project.id, addresses });
        const file = path.join(data.job.root, 'destroy.tfplan');
        await fs.chmod(file, 0o400);
        const hash = sha256(await fs.readFile(file));
        data.destroyPlan = { kind: 'destroy', file: 'destroy.tfplan', hash, summary, createdAt: now(), expiresAt: new Date(Date.now() + PLAN_TTL_MS).toISOString() };
        data.status = 'AWAITING_DESTROY_APPROVAL';
        await this.audit(dir, { action: 'destroy-plan', userId, planHash: hash, resources: summary.length });
        return this.save(dir, data);
      } catch (e) {
        await this.audit(dir, { action: 'destroy-plan', userId, result: 'REJECTED', error: e.safe ? e.message : 'Destroy planning failed' });
        throw e.safe ? e : fail('Destroy planning failed');
      } finally {
        for (const k of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']) delete env[k];
        await this.writeLog(data.job.dir, 'destroy-plan', logs).catch(() => {});
      }
    });
  }

  // Manifests and Dockerfiles for an applied project (no cloud calls).
  async artifacts(project, { tag }) {
    const data = await this.get(project.id);
    if (data.status !== 'APPLIED' || !data.outputs) throw fail('Apply the project infrastructure first');
    const { generateEksManifests } = require('./eksManifests');
    const comps = data.classification.components;
    const backend = comps.find(c => c.name === 'backend');
    return comps.map(c => ({
      component: c.name, dir: c.dir, dockerfile: c.dockerfile === 'generated' ? W.generateDockerfile(c) : null,
      manifests: generateEksManifests({ projectId: project.id, component: c, outputs: data.outputs.components[c.name], database: data.outputs.database, tag,
        backendHost: c.name === 'frontend' && backend ? `p${project.id}-backend` : null }),
    }));
  }
}

module.exports = { WorkloadInfrastructure, applyGate, TOOLS, PLAN_TTL_MS, APPROVAL_TTL_MS };
