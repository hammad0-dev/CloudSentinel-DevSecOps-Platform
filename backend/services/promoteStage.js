'use strict';
// CloudSentinel - "Promote to EKS" pipeline stage (Module 8). Runs after DAST, only when every earlier stage passed.
//
//   earlier stages passed? -> promote_target=eks? -> infrastructure APPLIED? (else analyze/confirm/plan/allowlist and
//   stop for manual approval, or approve the exact plan hash and apply when approval=auto_after_gates) -> target
//   cluster reachable? -> tag the staging image with the commit SHA -> push with the scoped profile (never overwrite a
//   tag) -> server-side dry run (Kyverno) -> apply the generated EKS manifests -> rollout status -> port-forward
//   health check -> on failure: kubectl rollout undo, stage FAILED.
//
// Terraform (through services/eksWorkloadEngine.js and all of its gates) provisions infrastructure only; pods are
// rolled out from the generated Kubernetes manifests. Kube context, registry, account and region come from the
// environment (PROMOTE_*), never from repository text. Every step is appended to the project's audit.jsonl.
// Nothing here prints or stores credentials: the registry password goes from `aws ecr get-login-password` to
// `docker login --password-stdin` in memory, with a private, temporary DOCKER_CONFIG.

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const http = require('node:http');
const { spawn } = require('node:child_process');
const W = require('./eksWorkload');

const STATUS = Object.freeze({
  PROMOTED: 'PROMOTED', ALREADY_PROMOTED: 'ALREADY_PROMOTED', APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  NEEDS_REVIEW: 'NEEDS_REVIEW', SKIPPED: 'SKIPPED', NOT_RUN: 'NOT_RUN', FAILED: 'FAILED',
});
const SUCCESS = new Set([STATUS.PROMOTED, STATUS.ALREADY_PROMOTED]);
const BASE_STAGES = ['SAST', 'Dependency', 'IaC', 'Deploy', 'DAST'];
const BUSY = ['APPLYING', 'DESTROYING', 'NEEDS_OPERATOR_REVIEW', 'AWAITING_DESTROY_APPROVAL', 'DESTROYED'];
const safeMsg = e => (e && e.safe ? e.message : 'unexpected error').slice(0, 400);
const promoteError = (message, code) => Object.assign(new Error(message), { safe: true, code });

function requiredStages(env = process.env) { return env.DAST_ACTIVE_ENABLED === 'true' ? [...BASE_STAGES, 'Active DAST'] : [...BASE_STAGES]; }

function settingsFrom(row) {
  return {
    target: row && row.promote_target === 'eks' ? 'eks' : 'none',
    approval: row && row.promote_approval === 'auto_after_gates' ? 'auto_after_gates' : 'manual',
  };
}

// Target configuration from the environment only. Any problem means "target unavailable" (the stage is skipped).
function targetConfig(env = process.env) {
  const c = {
    context: env.PROMOTE_KUBE_CONTEXT || '', registry: env.PROMOTE_REGISTRY || '', account: env.PROMOTE_AWS_ACCOUNT || '',
    region: env.PROMOTE_AWS_REGION || '', profile: env.PROMOTE_AWS_PROFILE || env.INFRA_AWS_PROFILE || 'cloudsentinel-dev',
    rolloutTimeoutSeconds: Number(env.PROMOTE_ROLLOUT_TIMEOUT_SECONDS || 180), healthPath: env.PROMOTE_HEALTH_PATH || '/',
  };
  const problems = [];
  if (!/^[A-Za-z0-9._@:-]{1,100}$/.test(c.context)) problems.push('PROMOTE_KUBE_CONTEXT not set');
  if (c.account !== W.ACCOUNT) problems.push(`PROMOTE_AWS_ACCOUNT must be the approved account ${W.ACCOUNT}`);
  if (c.region !== W.REGION) problems.push(`PROMOTE_AWS_REGION must be ${W.REGION}`);
  if (c.registry !== `${c.account}.dkr.ecr.${c.region}.amazonaws.com`) problems.push('PROMOTE_REGISTRY must be the ECR registry of that account and region');
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(c.profile)) problems.push('invalid PROMOTE_AWS_PROFILE');
  if (!Number.isInteger(c.rolloutTimeoutSeconds) || c.rolloutTimeoutSeconds < 30 || c.rolloutTimeoutSeconds > 900) problems.push('PROMOTE_ROLLOUT_TIMEOUT_SECONDS must be 30-900');
  if (!/^\/[A-Za-z0-9._~\/-]{0,100}$/.test(c.healthPath)) problems.push('invalid PROMOTE_HEALTH_PATH');
  return { ...c, problems };
}

// ---- infrastructure: APPLIED, or generate + plan + allowlist, then manual stop or gate-approved apply -------------
async function ensureInfrastructure({ project, settings, engine, principal, executionId, audit, result }) {
  let data = await engine.get(project.id);
  if (data.status === 'APPLIED' && data.outputs) return { data };
  if (BUSY.includes(data.status)) return { stop: [STATUS.NEEDS_REVIEW, `infrastructure is ${data.status}; a human must review it`] };
  const reusable = data.status === 'AWAITING_APPROVAL' && data.plan && Date.parse(data.plan.expiresAt) > Date.now() && !data.approval;
  if (!reusable) {
    data = await engine.analyze(project, principal);
    if (data.classification?.result !== 'CONTAINER') return { stop: [STATUS.NEEDS_REVIEW, `architecture needs human confirmation (${data.classification?.result || 'unknown'})`] };
    data = await engine.confirm(project, principal, {});
    if (data.status !== 'CONFIRMED') return { stop: [STATUS.NEEDS_REVIEW, `architecture needs human confirmation (${data.status})`] };
    try { data = await engine.plan(project, principal); }
    catch (e) {
      if (/^Plan rejected:/.test(e.message || '')) return { stop: [STATUS.NEEDS_REVIEW, `allowlist rejected the plan (${e.message}); a human must review it`] };
      return { stop: [STATUS.FAILED, `infrastructure plan failed: ${safeMsg(e)}`] };
    }
  }
  result.plan = { hash: data.plan.hash, resources: data.plan.summary.map(r => ({ actions: r.actions, type: r.type, address: r.address })), allowlist: 'ACCEPTED', expiresAt: data.plan.expiresAt };
  if (settings.approval !== 'auto_after_gates') {
    await audit({ action: 'promote-infrastructure-approval-required', planHash: data.plan.hash, resources: data.plan.summary.length });
    return { stop: [STATUS.APPROVAL_REQUIRED, 'infrastructure approval required'] };
  }
  const gate = engine.gate();
  if (!gate.enabled) return { stop: [STATUS.NEEDS_REVIEW, `automatic approval blocked: ${gate.reasons.join('; ')}`] };
  await engine.approve(project, principal, { hash: data.plan.hash, approvedBy: `pipeline gates (execution ${executionId})` });
  result.approvedBy = 'pipeline gates';
  try { data = await engine.apply(project, principal); }
  catch (e) { return { stop: [STATUS.FAILED, `infrastructure apply failed: ${safeMsg(e)}`] }; }
  return { data };
}

// ---- the stage ---------------------------------------------------------------------------------------------------
// ctx: { project, executionId, settings, stagesCompleted, earlierFailed, image: { localImageId, sourceCommit } }
// deps: { engine, kube, registry, audit(entry), config, required }
async function promote(ctx, deps) {
  const { project, executionId, settings = settingsFrom(null), stagesCompleted = [], earlierFailed = false, image = {} } = ctx;
  const result = { stage: 'Promote', target: settings.target, approval: settings.approval, startedAt: new Date().toISOString(), steps: [] };
  const audit = entry => deps.audit({ executionId, by: `pipeline:execution-${executionId}`, ...entry }).catch(() => {});
  const done = async (status, reason, extra = {}) => {
    Object.assign(result, extra, { status, reason, finishedAt: new Date().toISOString() });
    await audit({ action: 'promote-result', result: status, reason, tag: result.tag || null, approvedBy: result.approvedBy || null });
    return result;
  };
  const step = (name, outcome, detail) => result.steps.push({ name, outcome, ...(detail ? { detail: String(detail).slice(0, 300) } : {}), at: new Date().toISOString() });

  if (settings.target !== 'eks') return { stage: 'Promote', status: 'NOT_CONFIGURED' }; // existing behaviour, nothing recorded
  const required = deps.required || requiredStages();
  const missing = required.filter(s => !stagesCompleted.includes(s));
  if (earlierFailed || missing.length) return done(STATUS.NOT_RUN, `earlier stage did not pass: ${missing.join(', ') || 'pipeline failed'}`);
  if (!/^[a-f0-9]{40}$/.test(image.sourceCommit || '') || !/^sha256:[a-f0-9]{64}$/.test(image.localImageId || '')) return done(STATUS.FAILED, 'staging image identity (commit SHA and image ID) missing');
  const cfg = deps.config;
  if (cfg.problems.length) return done(STATUS.SKIPPED, `target unavailable: ${cfg.problems.join('; ')}`);
  await audit({ action: 'promote-start', commit: image.sourceCommit, image: image.localImageId });

  // 1. infrastructure
  let infra;
  try { infra = await ensureInfrastructure({ project, settings, engine: deps.engine, principal: `pipeline:execution-${executionId}`, executionId, audit, result }); }
  catch (e) { return done(STATUS.FAILED, `infrastructure step failed: ${safeMsg(e)}`); }
  if (infra.stop) { step('infrastructure', infra.stop[0]); return done(infra.stop[0], infra.stop[1]); }
  const data = infra.data;
  step('infrastructure', 'APPLIED', result.approvedBy ? `approved by ${result.approvedBy}` : 'already applied');

  // 2. target reachable
  if (!(await deps.kube.reachable().catch(() => false))) return done(STATUS.SKIPPED, 'target unavailable: cluster not reachable');
  step('cluster', 'REACHABLE', cfg.context);

  // 3. one component per staging image (the staging stage builds exactly one image)
  const comps = data.classification?.components || [];
  if (comps.length !== 1) return done(STATUS.NEEDS_REVIEW, `${comps.length}-component projects need one scanned image per component; the staging stage builds one`);
  const comp = comps[0];
  const repoUrl = data.outputs?.components?.[comp.name]?.repository_url || '';
  if (!repoUrl.startsWith(`${cfg.registry}/cloudsentinel/p-${project.id}-`)) return done(STATUS.FAILED, 'project repository is not in the configured registry');
  const tag = image.sourceCommit, ref = `${repoUrl}:${tag}`;
  Object.assign(result, { tag, image: ref, component: comp.name });
  let art;
  try { [art] = await deps.engine.artifacts(project, { tag }); }
  catch (e) { return done(STATUS.FAILED, `manifest generation failed: ${safeMsg(e)}`); }
  const ns = art.manifests.namespace, name = art.manifests.name;
  Object.assign(result, { namespace: ns, deployment: name });

  // 4. registry: never overwrite a tag
  let pushed = false;
  try {
    const existing = await deps.registry.describe(repoUrl, tag);
    if (existing.exists && existing.configDigest === image.localImageId) { step('push', 'SKIPPED', 'tag already holds this exact image'); }
    else if (existing.exists) {
      const running = await deps.kube.deployedImage(ns, name).catch(() => null);
      if (running === ref) {
        const health = await deps.kube.health(ns, name, comp.port, cfg.healthPath);
        step('health', health.ok ? 'OK' : 'FAILED', health.detail);
        await audit({ action: 'promote-push-skipped', tag, result: 'ALREADY_DEPLOYED' });
        return health.ok ? done(STATUS.ALREADY_PROMOTED, 'this commit is already promoted and healthy; nothing changed')
          : done(STATUS.FAILED, 'this commit is deployed but its health check failed');
      }
      await audit({ action: 'promote-push', tag, result: 'REFUSED_TAG_EXISTS' });
      return done(STATUS.FAILED, `tag ${tag} already exists in the registry with a different image; refusing to overwrite`);
    } else {
      await deps.registry.push(image.localImageId, ref);
      pushed = true;
      step('push', 'PUSHED', ref);
      await audit({ action: 'promote-push', tag, result: 'PUSHED', profile: cfg.profile });
    }
  } catch (e) {
    await audit({ action: 'promote-push', tag, result: 'FAILED', error: safeMsg(e) });
    if (e.code === 'CREDENTIALS_EXPIRED') return done(STATUS.NEEDS_REVIEW, safeMsg(e));
    if (e.code === 'TAG_EXISTS') return done(STATUS.FAILED, `tag ${tag} already exists in the registry; refusing to overwrite`);
    return done(STATUS.FAILED, `registry push failed: ${safeMsg(e)}`);
  }

  // 5. dry run (Kyverno admission) + apply + rollout + health; roll back on any failure after apply
  try { await deps.kube.apply(art.manifests.yaml, { dryRun: true }); step('dry-run', 'ADMITTED'); }
  catch (e) { await audit({ action: 'promote-apply', tag, result: 'DENIED_BY_ADMISSION' }); return done(STATUS.FAILED, `admission dry run refused the manifests: ${safeMsg(e)}`); }
  const previous = await deps.kube.deployedImage(ns, name).catch(() => null);
  try { await deps.kube.apply(art.manifests.yaml, { dryRun: false }); step('apply', 'APPLIED'); await audit({ action: 'promote-apply', tag, result: 'APPLIED', previousImage: previous }); }
  catch (e) { await audit({ action: 'promote-apply', tag, result: 'FAILED' }); return done(STATUS.FAILED, `kubectl apply failed: ${safeMsg(e)}`); }
  const rollout = await deps.kube.rollout(ns, name, cfg.rolloutTimeoutSeconds).catch(e => ({ ok: false, detail: safeMsg(e) }));
  step('rollout', rollout.ok ? 'OK' : 'FAILED', rollout.detail);
  let health = { ok: false, detail: 'not run' };
  if (rollout.ok) { health = await deps.kube.health(ns, name, comp.port, cfg.healthPath).catch(e => ({ ok: false, detail: safeMsg(e) })); step('health', health.ok ? 'OK' : 'FAILED', health.detail); }
  if (!rollout.ok || !health.ok) {
    const undo = previous ? await deps.kube.undo(ns, name, cfg.rolloutTimeoutSeconds).catch(e => ({ ok: false, detail: safeMsg(e) })) : { ok: false, detail: 'no previous revision to roll back to' };
    step('rollback', undo.ok ? 'OK' : 'FAILED', undo.detail);
    await audit({ action: 'promote-rollback', tag, result: undo.ok ? 'ROLLED_BACK' : 'ROLLBACK_FAILED', restoredImage: undo.ok ? previous : null });
    return done(STATUS.FAILED, `${!rollout.ok ? 'rollout' : 'health check'} failed; rollback ${undo.ok ? 'done' : 'not possible: ' + undo.detail}`, { rolledBack: undo.ok });
  }
  await audit({ action: 'promote-rollout', tag, result: 'HEALTHY', health: health.detail });
  return done(STATUS.PROMOTED, `${ref.split('/').pop()} rolled out to ${cfg.context} and is healthy`, { pushed });
}

// ---- real adapters ---------------------------------------------------------------------------------------------
function exec(file, args, { env, input, timeout = 120000, cwd } = {}) {
  return new Promise(resolve => {
    const child = spawn(file, args, { env, cwd, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', done = false;
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, timeout);
    child.stdout.on('data', d => { if (stdout.length < 4e6) stdout += d; });
    child.stderr.on('data', d => { if (stderr.length < 1e6) stderr += d; });
    child.on('error', e => { if (!done) { done = true; clearTimeout(timer); resolve({ code: 127, stdout, stderr: String(e.message) }); } });
    child.on('close', code => { if (!done) { done = true; clearTimeout(timer); resolve({ code, stdout, stderr }); } });
    if (input !== undefined) child.stdin.end(input); else child.stdin.end();
  });
}
const tail = s => String(s || '').trim().split('\n').slice(-3).join(' | ').replace(/[A-Za-z0-9+/=]{40,}/g, '[REDACTED]').slice(0, 300);

function toolEnv(extra = {}) {
  return { PATH: `${path.join(os.homedir(), '.local/bin')}:/usr/local/bin:/usr/bin:/bin:/snap/bin`, HOME: os.homedir(), LANG: 'C.UTF-8', AWS_PAGER: '', ...extra };
}

function kubeAdapter(cfg, { run = exec, kubectl = process.env.PROMOTE_KUBECTL_BIN || 'kubectl', transform = y => y } = {}) {
  const k = (args, opts = {}) => run(kubectl, ['--context', cfg.context, ...args], { env: toolEnv(), ...opts });
  return {
    async reachable() { const r = await k(['get', '--raw=/readyz', '--request-timeout=10s'], { timeout: 20000 }); return r.code === 0 && /ok/.test(r.stdout); },
    async deployedImage(ns, name) {
      const r = await k(['-n', ns, 'get', 'deployment', name, '-o', 'jsonpath={.spec.template.spec.containers[0].image}', '--request-timeout=20s']);
      return r.code === 0 && r.stdout.trim() ? r.stdout.trim() : null;
    },
    async apply(yaml, { dryRun }) {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cs-promote-'));
      try {
        await fs.chmod(dir, 0o700);
        const file = path.join(dir, 'manifests.yaml');
        await fs.writeFile(file, transform(yaml), { mode: 0o600 });
        const r = await k(['apply', ...(dryRun ? ['--dry-run=server'] : []), '-f', file, '--request-timeout=60s'], { timeout: 120000 });
        if (r.code !== 0) throw promoteError(tail(r.stderr || r.stdout), 'KUBECTL_APPLY');
        return tail(r.stdout);
      } finally { await fs.rm(dir, { recursive: true, force: true }); }
    },
    async rollout(ns, name, seconds) {
      const r = await k(['-n', ns, 'rollout', 'status', `deployment/${name}`, `--timeout=${seconds}s`], { timeout: (seconds + 30) * 1000 });
      return { ok: r.code === 0, detail: tail(r.code === 0 ? r.stdout : r.stderr || r.stdout) };
    },
    async undo(ns, name, seconds) {
      const u = await k(['-n', ns, 'rollout', 'undo', `deployment/${name}`]);
      if (u.code !== 0) return { ok: false, detail: tail(u.stderr) };
      const r = await this.rollout(ns, name, seconds);
      return { ok: r.ok, detail: `undo: ${tail(u.stdout)}; ${r.detail}` };
    },
    async health(ns, name, port, healthPath = '/') {
      const local = await freePort();
      const child = spawn(kubectl, ['--context', cfg.context, '-n', ns, 'port-forward', `deployment/${name}`, `${local}:${port}`, '--address', '127.0.0.1'], { env: toolEnv(), stdio: ['ignore', 'pipe', 'pipe'] });
      try {
        await new Promise((resolve, reject) => {
          const t = setTimeout(() => reject(promoteError('port-forward did not start', 'PORT_FORWARD')), 20000);
          child.stdout.on('data', d => { if (/Forwarding from/.test(String(d))) { clearTimeout(t); resolve(); } });
          child.on('close', () => { clearTimeout(t); reject(promoteError('port-forward exited', 'PORT_FORWARD')); });
        });
        let last = 'no response';
        for (let i = 0; i < 5; i++) {
          const code = await httpStatus(`http://127.0.0.1:${local}${healthPath}`).catch(e => { last = e.message; return 0; });
          if (code >= 200 && code < 400) return { ok: true, detail: `GET ${healthPath} -> ${code} via port-forward` };
          if (code) last = `HTTP ${code}`;
          await new Promise(r => setTimeout(r, 2000));
        }
        return { ok: false, detail: `GET ${healthPath} via port-forward: ${last}` };
      } catch (e) { return { ok: false, detail: safeMsg(e) }; }
      finally { child.kill('SIGTERM'); }
    },
  };
}
function freePort() { return new Promise((resolve, reject) => { const s = net.createServer(); s.unref(); s.on('error', reject); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); }); }
function httpStatus(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: 5000 }, res => { res.resume(); resolve(res.statusCode); });
    req.on('timeout', () => req.destroy(new Error('timeout'))); req.on('error', reject);
  });
}

// ECR with the scoped profile. Tag immutability is checked here AND enforced by the repository (IMMUTABLE).
function ecrAdapter(cfg, { run = exec, aws = process.env.INFRA_AWS_BIN || path.join(os.homedir(), '.local/bin/aws'), docker = process.env.PROMOTE_DOCKER_BIN || 'docker' } = {}) {
  const awsEnv = toolEnv({ AWS_PROFILE: cfg.profile, AWS_REGION: cfg.region, AWS_DEFAULT_REGION: cfg.region, AWS_EC2_METADATA_DISABLED: 'true' });
  const repoName = repoUrl => { const m = new RegExp(`^${cfg.registry.replace(/\./g, '\\.')}/(cloudsentinel/p-[1-9][0-9]*-(app|frontend|backend))$`).exec(repoUrl); if (!m) throw promoteError('repository outside the configured registry', 'REGISTRY'); return m[1]; };
  const awsFail = r => /expired|login|sso|token/i.test(r.stderr) ? promoteError(`AWS login for profile ${cfg.profile} has expired; run: aws login --profile ${cfg.profile}`, 'CREDENTIALS_EXPIRED') : promoteError(`aws: ${tail(r.stderr)}`, 'AWS');
  async function describe(repoUrl, tag) {
    const r = await run(aws, ['ecr', 'batch-get-image', '--repository-name', repoName(repoUrl), '--image-ids', `imageTag=${tag}`, '--output', 'json'], { env: awsEnv, timeout: 30000 });
    if (r.code !== 0) throw awsFail(r);
    const out = JSON.parse(r.stdout || '{}');
    const img = (out.images || [])[0];
    if (!img) { if ((out.failures || []).every(f => f.failureCode === 'ImageTagDoesNotMatchDigest' || f.failureCode === 'ImageNotFound')) return { exists: false }; throw promoteError('registry lookup failed', 'AWS'); }
    let digest = null; try { digest = JSON.parse(img.imageManifest).config?.digest || null; } catch { /* unknown manifest */ }
    return { exists: true, configDigest: digest };
  }
  async function push(localImageId, ref) {
    const dockerConfig = await fs.mkdtemp(path.join(os.tmpdir(), 'cs-promote-docker-'));
    const dEnv = toolEnv({ DOCKER_CONFIG: dockerConfig, ...(process.env.DOCKER_HOST ? { DOCKER_HOST: process.env.DOCKER_HOST } : {}) });
    try {
      await fs.chmod(dockerConfig, 0o700);
      const pw = await run(aws, ['ecr', 'get-login-password'], { env: awsEnv, timeout: 30000 });
      if (pw.code !== 0 || !pw.stdout.trim()) throw awsFail(pw);
      const login = await run(docker, ['login', '--username', 'AWS', '--password-stdin', cfg.registry], { env: dEnv, input: pw.stdout.trim(), timeout: 60000 });
      pw.stdout = '';
      if (login.code !== 0) throw promoteError('registry login failed', 'REGISTRY');
      const t = await run(docker, ['tag', localImageId, ref], { env: dEnv });
      if (t.code !== 0) throw promoteError(`docker tag failed: ${tail(t.stderr)}`, 'DOCKER');
      const p = await run(docker, ['push', ref], { env: dEnv, timeout: 15 * 60 * 1000 });
      if (p.code !== 0) throw promoteError(/already exists|immutable/i.test(p.stderr) ? 'tag already exists (immutable)' : `docker push failed: ${tail(p.stderr)}`, /already exists|immutable/i.test(p.stderr) ? 'TAG_EXISTS' : 'DOCKER');
      const check = await describe(ref.slice(0, ref.lastIndexOf(':')), ref.slice(ref.lastIndexOf(':') + 1));
      if (!check.exists || check.configDigest !== localImageId) throw promoteError('pushed tag does not hold the staging image', 'DOCKER');
    } finally {
      await run(docker, ['logout', cfg.registry], { env: dEnv, timeout: 20000 }).catch(() => {});
      await fs.rm(dockerConfig, { recursive: true, force: true });
    }
  }
  return { describe, push };
}

// ---- pipeline entry ------------------------------------------------------------------------------------------------
async function loadSettings(pool, projectId) {
  // Fail closed to "none" (no promotion, existing behaviour): migration 024 not applied (42703), DB error, odd rows.
  try { return settingsFrom((await pool.query('SELECT promote_target, promote_approval FROM projects WHERE id=$1', [projectId]))?.rows?.[0]); }
  catch (e) { if (!e || e.code !== '42703') console.error('[promote] settings unavailable; promotion not attempted'); return settingsFrom(null); }
}

async function runForPipeline({ pool, projectId, executionId, userId, stagesCompleted, deployResult, deps: given = {} }) {
  const settings = await loadSettings(pool, projectId);
  if (settings.target !== 'eks') return null;
  let result;
  try {
    const { ownedProject, repositoryFiles } = require('./infrastructurePlanning');
    const project = await ownedProject(pool, userId, projectId);
    const { WorkloadInfrastructure } = require('./eksWorkloadEngine');
    const engine = given.engine || new WorkloadInfrastructure({ source: p => repositoryFiles(p, { withCode: true }) });
    const config = given.config || targetConfig();
    result = await promote({ project, executionId, settings, stagesCompleted, image: { localImageId: deployResult?.localImageId, sourceCommit: String(deployResult?.sourceCommit || '').trim() } }, {
      engine, config, kube: given.kube || kubeAdapter(config), registry: given.registry || ecrAdapter(config),
      audit: given.audit || (entry => engine.recordAudit(project.id, entry)),
    });
  } catch (e) {
    result = { stage: 'Promote', status: STATUS.FAILED, reason: `promote stage error: ${safeMsg(e)}`, finishedAt: new Date().toISOString() };
  }
  try { await pool.query('UPDATE pipeline_executions SET promote_result=$1 WHERE id=$2 AND project_id=$3', [JSON.stringify(result), executionId, projectId]); }
  catch { console.error('[promote] could not record the stage result (is migration 024 applied?)'); }
  return result;
}

module.exports = { promote, runForPipeline, settingsFrom, targetConfig, requiredStages, kubeAdapter, ecrAdapter, exec, STATUS, SUCCESS, loadSettings };
