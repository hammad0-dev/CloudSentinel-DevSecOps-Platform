'use strict';
// Module 9 / SRS FR-20: Secrets Management screen, metadata only.
//
// Lists the Kubernetes Secrets in a project's CloudSentinel-owned namespaces on the configured kube context
// (KUBERNETES_MINIKUBE_CONTEXT, default minikube; the current context must match). Secret VALUES never reach this
// process: kubectl prints a go-template that emits only name, type, timestamps, owner kinds, labels and the NUMBER
// of data keys (one "." per key). Annotations are never read (kubectl's last-applied-configuration annotation can
// contain the data). Policies (rotation days, expiry date) come from the secret_policies table (migration 025).
//
// Roles: the project owner, and platform admins listed in SECRETS_ADMIN_EMAILS, may view and set policies. Anyone
// else gets 404 (the project's existence is not disclosed).
const { execFile } = require('node:child_process');
const execute = require('node:util').promisify(execFile);
const { PROJECT_ID_LABEL, MANAGED_BY_LABEL, getProjectNamespace } = require('./kubernetesNamespace');

const MASK = '••••••••';
const DAY = 24 * 60 * 60 * 1000;
const NAME_RE = /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/;
const ESO_LABEL = 'reconcile.external-secrets.io/created-by';
const expectedContext = () => process.env.KUBERNETES_MINIKUBE_CONTEXT || 'minikube';
const warnDays = (env = process.env) => { const n = Number.parseInt(env.SECRETS_EXPIRY_WARN_DAYS || '', 10); return Number.isInteger(n) && n >= 0 && n <= 365 ? n : 14; };

// One line per secret, tab-separated. "." per data key: the key names and values are not printed.
const TEMPLATE = '{{range .items}}{{.metadata.name}}{{"\\t"}}{{.type}}{{"\\t"}}{{.metadata.creationTimestamp}}{{"\\t"}}'
  + '{{range $k, $v := .data}}.{{end}}{{"\\t"}}{{range .metadata.ownerReferences}}{{.kind}},{{end}}{{"\\t"}}'
  + '{{range $k, $v := .metadata.labels}}{{$k}}={{$v}};{{end}}{{"\\t"}}{{range .metadata.managedFields}}{{.time}},{{end}}{{"\\n"}}{{end}}';

async function kubectl(args) {
  const { stdout } = await execute('kubectl', args, { timeout: 10000, maxBuffer: 2 * 1024 * 1024 });
  return stdout;
}

function isAdmin(user, env = process.env) {
  const admins = String(env.SECRETS_ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  return !!user?.email && admins.includes(String(user.email).toLowerCase());
}

// Returns { projectId, role } or { code, body } for a refusal.
async function access(pool, user, id) {
  if (!/^[1-9]\d*$/.test(String(id)) || !Number.isSafeInteger(Number(id))) return { code: 400, body: { error: 'Valid project required' } };
  const projectId = Number(id);
  const { rows } = await pool.query('SELECT id, user_id FROM projects WHERE id = $1', [projectId]);
  if (!rows.length) return { code: 404, body: { error: 'Project not found' } };
  if (rows[0].user_id === user?.id) return { projectId, role: 'owner' };
  if (isAdmin(user)) return { projectId, role: 'admin' };
  return { code: 404, body: { error: 'Project not found' } };
}

function source(type, owners, labels) {
  if (owners.includes('ExternalSecret') || labels[ESO_LABEL]) return 'External Secrets Operator';
  if (type === 'helm.sh/release.v1') return 'Helm release';
  if (type === 'kubernetes.io/service-account-token') return 'Kubernetes service account token';
  if (type === 'kubernetes.io/dockerconfigjson' || type === 'kubernetes.io/dockercfg') return 'Image pull secret';
  if (type === 'kubernetes.io/tls') return 'TLS certificate';
  if (labels[MANAGED_BY_LABEL] === 'cloudsentinel' || labels['managed-by'] === 'cloudsentinel') return 'CloudSentinel deployment';
  return 'Kubernetes Secret (kubectl or an operator)';
}

function parseLines(stdout, namespace) {
  const out = [];
  for (const line of String(stdout || '').split('\n')) {
    if (!line.trim()) continue;
    const [name, type, created, dots = '', ownerList = '', labelList = '', fieldTimes = ''] = line.split('\t');
    if (!NAME_RE.test(name || '') || name.length > 253) throw Error('Unexpected secret name in kubectl output');
    if (/[^.]/.test(dots)) throw Error('Unexpected key count in kubectl output');
    const labels = Object.fromEntries(labelList.split(';').filter(Boolean).map(p => { const i = p.indexOf('='); return [p.slice(0, i), p.slice(i + 1)]; }));
    const owners = ownerList.split(',').filter(Boolean);
    const times = [created, ...fieldTimes.split(',')].filter(t => t && !Number.isNaN(Date.parse(t)));
    const lastChangedAt = times.sort().at(-1) || null;
    out.push({ namespace, name, type: type || 'Opaque', source: source(type, owners, labels), keysCount: dots.length,
      createdAt: Number.isNaN(Date.parse(created)) ? null : created, lastChangedAt, value: MASK });
  }
  return out;
}

const dayStart = d => Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());

function expiryStatus(expiresAt, now = new Date(), warn = warnDays()) {
  if (!expiresAt) return { status: 'NOT_SET', text: 'No expiry date set' };
  const exp = new Date(`${String(expiresAt).slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(exp.getTime())) return { status: 'NOT_SET', text: 'No expiry date set' };
  const daysLeft = Math.round((exp.getTime() - dayStart(now)) / DAY);
  if (daysLeft < 0) return { status: 'EXPIRED', daysLeft, text: `Expired ${-daysLeft} day(s) ago` };
  if (daysLeft <= warn) return { status: 'EXPIRING_SOON', daysLeft, text: daysLeft === 0 ? 'Expires today' : `Expires in ${daysLeft} day(s)` };
  return { status: 'OK', daysLeft, text: `Expires in ${daysLeft} day(s)` };
}

function rotationStatus(rotationDays, lastChangedAt, now = new Date()) {
  if (!rotationDays) return { status: 'NO_POLICY', text: 'No rotation policy' };
  if (!lastChangedAt) return { status: 'UNKNOWN', text: 'Last change time unknown' };
  const age = Math.floor((now.getTime() - Date.parse(lastChangedAt)) / DAY);
  const dueIn = rotationDays - age;
  if (dueIn < 0) return { status: 'OVERDUE', ageDays: age, text: `Rotation overdue by ${-dueIn} day(s) (every ${rotationDays} days; last changed ${age} day(s) ago)` };
  return { status: 'WITHIN_POLICY', ageDays: age, text: `Next rotation due in ${dueIn} day(s) (every ${rotationDays} days)` };
}

// Owned namespaces on the expected context; throws when the context does not match or ownership is unverifiable.
async function ownedNamespaces(projectId, run) {
  const ctx = expectedContext();
  const current = String(await run(['config', 'current-context'])).trim();
  if (current !== ctx) throw Object.assign(Error('Context mismatch'), { code: 'CONTEXT_MISMATCH', current });
  const raw = await run(['--context', ctx, '--request-timeout=5s', 'get', 'namespaces', '-l', `${PROJECT_ID_LABEL}=${projectId},${MANAGED_BY_LABEL}=cloudsentinel`, '-o', 'jsonpath={range .items[*]}{.metadata.name}{"\\n"}{end}']);
  const names = String(raw).split('\n').map(s => s.trim()).filter(Boolean);
  if (names.length > 20 || names.some(n => n !== getProjectNamespace(projectId))) throw Error('Namespace ownership unverifiable');
  return { ctx, names };
}

async function listSecrets(projectId, run = kubectl) {
  const { ctx, names } = await ownedNamespaces(projectId, run);
  const secrets = [];
  for (const ns of names) {
    secrets.push(...parseLines(await run(['--context', ctx, '--request-timeout=5s', 'get', 'secrets', '-n', ns, '-o', `go-template=${TEMPLATE}`]), ns));
  }
  return { context: ctx, namespaces: names, secrets };
}

async function esoInstalled(ctx, run) {
  try { await run(['--context', ctx, '--request-timeout=5s', 'get', 'crd', 'externalsecrets.external-secrets.io', '-o', 'name']); return true; }
  catch { return false; }
}

// Rotation is not a button: nothing on this stack can rotate a secret value safely from the UI.
function rotationGuide(projectId, esoPresent, ctx) {
  const command = `scripts/rotate-secret.sh --secret-id cloudsentinel/p-${projectId}/<app|frontend|backend> --key <KEY>`;
  return esoPresent
    ? { available: true, command, text: `External Secrets Operator is installed on ${ctx}. Run ${command} against a configured AWS Secrets Manager target; ExternalSecret-managed secrets pick up the new version within their refreshInterval (mounted files without a redeploy, environment variables after a pod restart).` }
    : { available: false, command, text: `Not available on this cluster: ${ctx} has no External Secrets Operator, so no secret here is synced from AWS Secrets Manager. scripts/rotate-secret.sh rotates AWS Secrets Manager secrets; run it against a configured target (an EKS cluster with ESO). The UI does not rotate secrets.` };
}

const undefinedTable = e => e?.code === '42P01';

async function loadPolicies(pool, projectId) {
  try {
    const { rows } = await pool.query('SELECT namespace, secret_name, rotation_days, expires_at, updated_at FROM secret_policies WHERE project_id = $1', [projectId]);
    return { available: true, byKey: new Map(rows.map(r => [`${r.namespace}/${r.secret_name}`, r])) };
  } catch (e) {
    if (undefinedTable(e)) return { available: false, byKey: new Map() };
    throw e;
  }
}

const isoDate = d => (d instanceof Date ? d.toISOString() : String(d)).slice(0, 10);

async function projectSecrets(pool, user, id, { run = kubectl, now = new Date() } = {}) {
  const a = await access(pool, user, id);
  if (a.code) return a;
  const base = { projectId: a.projectId, role: a.role, canEditPolicies: true, observedAt: now.toISOString(), expiryWarnDays: warnDays() };
  let listing;
  try { listing = await listSecrets(a.projectId, run); }
  catch (e) {
    return { code: 200, body: { ...base, status: 'not_connected', secrets: [], rotation: rotationGuide(a.projectId, false, expectedContext()),
      reason: e.code === 'CONTEXT_MISMATCH' ? `Current kube context is not ${expectedContext()}` : `Kubernetes unavailable on ${expectedContext()} or namespace ownership unverifiable` } };
  }
  const policies = await loadPolicies(pool, a.projectId);
  const secrets = listing.secrets.map(s => {
    const p = policies.byKey.get(`${s.namespace}/${s.name}`) || null;
    const policy = p ? { rotationDays: p.rotation_days, expiresAt: p.expires_at ? isoDate(p.expires_at) : null, updatedAt: p.updated_at } : null;
    return { ...s, ageDays: s.lastChangedAt ? Math.floor((now.getTime() - Date.parse(s.lastChangedAt)) / DAY) : null,
      policy, expiry: expiryStatus(policy?.expiresAt, now), rotation: rotationStatus(policy?.rotationDays, s.lastChangedAt, now) };
  });
  const status = listing.namespaces.length ? 'observed' : 'not_deployed';
  return { code: 200, body: { ...base, canEditPolicies: policies.available, status, context: listing.context, namespaces: listing.namespaces, policiesAvailable: policies.available,
    secrets, rotation: rotationGuide(a.projectId, await esoInstalled(listing.context, run), listing.context) } };
}

function validatePolicy(body) {
  const { namespace, name } = body || {};
  let { rotationDays, expiresAt } = body || {};
  if (typeof namespace !== 'string' || typeof name !== 'string' || !NAME_RE.test(name) || name.length > 253) return 'namespace and name are required';
  if (rotationDays === '' || rotationDays === undefined) rotationDays = null;
  if (rotationDays !== null && !(Number.isInteger(Number(rotationDays)) && Number(rotationDays) >= 1 && Number(rotationDays) <= 3650)) return 'rotationDays must be a whole number from 1 to 3650, or empty';
  if (expiresAt === '' || expiresAt === undefined) expiresAt = null;
  if (expiresAt !== null && (!/^\d{4}-\d{2}-\d{2}$/.test(String(expiresAt)) || Number.isNaN(Date.parse(`${expiresAt}T00:00:00Z`)))) return 'expiresAt must be a date (YYYY-MM-DD), or empty';
  return { namespace, name, rotationDays: rotationDays === null ? null : Number(rotationDays), expiresAt };
}

// Owner or admin only (access()). The secret must exist in the project's namespace on the current context.
async function setPolicy(pool, user, id, body, { run = kubectl } = {}) {
  const a = await access(pool, user, id);
  if (a.code) return a;
  const v = validatePolicy(body);
  if (typeof v === 'string') return { code: 400, body: { error: v } };
  if (v.namespace !== getProjectNamespace(a.projectId)) return { code: 400, body: { error: 'Namespace does not belong to this project' } };
  let listing;
  try { listing = await listSecrets(a.projectId, run); } catch { return { code: 503, body: { error: 'Kubernetes unavailable; the secret could not be verified' } }; }
  if (!listing.secrets.some(s => s.namespace === v.namespace && s.name === v.name)) return { code: 404, body: { error: 'Secret not found in this project namespace' } };
  try {
    if (v.rotationDays === null && v.expiresAt === null) {
      await pool.query('DELETE FROM secret_policies WHERE project_id = $1 AND namespace = $2 AND secret_name = $3', [a.projectId, v.namespace, v.name]);
      return { code: 200, body: { projectId: a.projectId, namespace: v.namespace, name: v.name, policy: null } };
    }
    const { rows } = await pool.query(
      `INSERT INTO secret_policies (project_id, namespace, secret_name, rotation_days, expires_at, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (project_id, namespace, secret_name)
       DO UPDATE SET rotation_days = EXCLUDED.rotation_days, expires_at = EXCLUDED.expires_at, updated_by = EXCLUDED.updated_by, updated_at = NOW()
       RETURNING rotation_days, expires_at, updated_at`,
      [a.projectId, v.namespace, v.name, v.rotationDays, v.expiresAt, user.id]);
    const p = rows[0];
    return { code: 200, body: { projectId: a.projectId, namespace: v.namespace, name: v.name,
      policy: { rotationDays: p.rotation_days, expiresAt: p.expires_at ? isoDate(p.expires_at) : null, updatedAt: p.updated_at } } };
  } catch (e) {
    if (undefinedTable(e)) return { code: 503, body: { error: 'Secret policies are unavailable: apply migration 025 (npm run migrate:secrets)' } };
    throw e;
  }
}

// FR-20.4 notification: one in-app security alert per secret whose expiry date is within the warning window or
// passed (deduplicated by alertStore on rule + key). Metadata only.
async function expiryDetections(pool, now = new Date(), warn = warnDays()) {
  let rows;
  try {
    ({ rows } = await pool.query(
      `SELECT project_id, namespace, secret_name, expires_at FROM secret_policies
       WHERE expires_at IS NOT NULL AND expires_at <= ($1::date + $2::int)`, [isoDate(now), warn]));
  } catch (e) { if (undefinedTable(e)) return []; throw e; }
  return rows.map(r => {
    const exp = expiryStatus(isoDate(r.expires_at), now, warn);
    return { rule: 'secret_expiring', severity: exp.status === 'EXPIRED' ? 'HIGH' : 'MEDIUM', source: 'backend', projectId: r.project_id,
      details: { key: `${r.project_id}/${r.namespace}/${r.secret_name}/${isoDate(r.expires_at)}`, namespace: r.namespace, secret: r.secret_name,
        expiresAt: isoDate(r.expires_at), description: `Secret ${r.namespace}/${r.secret_name}: ${exp.text.toLowerCase()} (policy set on the Secrets Management screen)` } };
  });
}

function startExpiryNotifier({ pool, createAlert, intervalMs = 15 * 60 * 1000, onError = () => {} }) {
  const tick = async () => {
    try { for (const d of await expiryDetections(pool)) { try { await createAlert(d); } catch (e) { onError(e); } } }
    catch (e) { onError(e); }
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref?.();
  setTimeout(tick, 5000).unref?.();
  return { tick, stop: () => clearInterval(timer) };
}

module.exports = { MASK, TEMPLATE, access, isAdmin, parseLines, source, expiryStatus, rotationStatus, listSecrets, projectSecrets,
  validatePolicy, setPolicy, expiryDetections, startExpiryNotifier, rotationGuide, warnDays };
