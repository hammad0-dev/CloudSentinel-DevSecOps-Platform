'use strict';
// CloudSentinel - EKS container workload generator (Modules 8, 9, 10).
//
// detection -> classification -> validated terraform.tfvars.json -> fixed templates -> plan allowlist
//
// The repository is only ever *read*. Nothing from it is written into a .tf file: the Terraform templates in
// terraform/templates/eks-project and terraform/modules/project-{workload,database} are fixed and reviewed, and
// the generator writes only values that pass the patterns below into terraform.tfvars.json.
// Custom/unknown architectures, unsupported databases (MongoDB, Redis, SQLite, ...) and uncertain entrypoints
// produce a MANUAL_REVIEW / CONFIRM_ENTRYPOINT result instead of a guess.

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { analyze } = require('./repositoryArchitecture');

const ACCOUNT = '229032674007';
const REGION = 'ap-south-1';
const PROTECTED_PROJECTS = [11, 13, 17];
const MODULE_TAG = '8-eks-workload';
const DEFAULT_CLUSTER = 'cloudsentinel-eks';
const REPO_ROOT = path.resolve(__dirname, '../..');
const TEMPLATE_DIRS = ['terraform/templates/eks-project', 'terraform/modules/project-workload', 'terraform/modules/project-database'];
const ECR_HOST = `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com`;

const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const COMPONENT_NAMES = ['app', 'frontend', 'backend'];
const SUPPORTED_DATABASES = { PostgreSQL: 'postgres', MySQL: 'mysql' };
// Provided by the platform, never stored as project secrets.
const PLATFORM_ENV = new Set(['PORT', 'HOST', 'NODE_ENV', 'HOME', 'PATH', 'PWD', 'HOSTNAME', 'TZ', 'LANG', 'PYTHONUNBUFFERED',
  'PYTHONDONTWRITEBYTECODE', 'PYTHONPATH', 'CI', 'DEBUG', 'BACKEND_URL' /* three-tier frontend: from the ConfigMap */]);
// Database settings come from RDS outputs (ConfigMap) and the RDS-managed secret (ExternalSecret).
const DB_ENV = new Set(['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DATABASE_URL']);
const FRONTEND_DEPS = ['react', 'react-dom', 'vue', 'next', '@angular/core', 'svelte', 'vite'];
const BACKEND_DEPS = ['express', 'fastify', 'koa', '@nestjs/core', 'hapi', '@hapi/hapi'];
const PY_FRAMEWORKS = ['fastapi', 'flask', 'django', 'starlette'];
const PY_ENTRYPOINTS = ['app.py', 'main.py', 'wsgi.py'];
const BASE_IMAGES = { python: 'python:3.12.15-slim-bookworm', node: 'node:22.23.3-alpine' };

const fail = (message, status = 400) => Object.assign(new Error(message), { safe: true, status });
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const posixDir = file => { const d = path.posix.dirname(file); return d === '.' ? '' : d; };
const inDir = (dir, file) => (dir === '' ? !file.includes('/') : file.startsWith(dir + '/') && !file.slice(dir.length + 1).includes('/'));

// ---- source ------------------------------------------------------------------------------------------------
const MANIFEST = /(^|\/)(package.json|requirements[^/]*\.txt|pyproject.toml|Pipfile|setup.cfg|pom.xml|build.gradle[^/]*|go.mod|Dockerfile[^/]*|(?:docker-)?compose[^/]*\.ya?ml|[^/]+\.html?)$/;
const CODE = /(^|\/)([^/]+\.(?:py|js|mjs|cjs)|\.env\.example|\.env\.sample)$/;
const SKIP_DIR = /(^|\/)(node_modules|\.git|\.venv|venv|__pycache__|dist|build|coverage|\.terraform)(\/|$)/;

// Bounded read of a local checkout (CLI and tests). Returns the same shape as the GitHub source plus `paths`.
async function localSource(dir, { maxPaths = 2000, maxFiles = 60, maxBytes = 65536 } = {}) {
  const root = await fs.realpath(dir);
  const paths = [];
  async function walk(rel) {
    for (const entry of await fs.readdir(path.join(root, rel), { withFileTypes: true })) {
      const p = rel ? `${rel}/${entry.name}` : entry.name;
      if (SKIP_DIR.test(p)) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) await walk(p);
      else if (entry.isFile()) { paths.push(p); if (paths.length > maxPaths) throw fail('Repository too large for bounded analysis'); }
    }
  }
  await walk('');
  paths.sort();
  const files = {}, code = {};
  const wanted = paths.filter(p => MANIFEST.test(p) || CODE.test(p));
  if (wanted.length > maxFiles) throw fail('Repository needs manual analysis: too many manifests or source files');
  for (const p of wanted) {
    const st = await fs.stat(path.join(root, p));
    if (st.size > maxBytes) throw fail('Repository file exceeds analysis bound');
    const text = await fs.readFile(path.join(root, p), 'utf8');
    if (MANIFEST.test(p)) files[p] = text; else code[p] = text;
  }
  const commit = sha256(JSON.stringify([paths, files, code]));
  return { commit, files, code, paths, local: true };
}

// ---- detection helpers -------------------------------------------------------------------------------------
function envNamesFrom(text) {
  const names = new Set();
  const patterns = [
    /os\.environ\.get\(\s*["']([A-Z][A-Z0-9_]*)["']/g, /os\.getenv\(\s*["']([A-Z][A-Z0-9_]*)["']/g,
    /os\.environ\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]/g, /process\.env\.([A-Z][A-Z0-9_]*)/g,
    /process\.env\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]/g,
  ];
  for (const re of patterns) for (const m of text.matchAll(re)) names.add(m[1]);
  return names;
}
function envFileNames(text) {
  const names = new Set();
  for (const line of text.split('\n')) { const m = /^\s*([A-Z][A-Z0-9_]*)\s*=/.exec(line); if (m) names.add(m[1]); }
  return names;
}
function portFrom(text) {
  const patterns = [/listen\s*=\s*["'][^"':]*:(\d{2,5})["']/, /\bport\s*=\s*(\d{2,5})\b/i, /["']PORT["']\s*,\s*["']?(\d{2,5})/,
    /(?<![A-Za-z0-9_])PORT\s*\|\|\s*(\d{2,5})/, /\.listen\(\s*(\d{2,5})/, /(?<![A-Za-z0-9_])PORT\s*\?\?\s*(\d{2,5})/];
  for (const re of patterns) { const m = re.exec(text); if (m) return Number(m[1]); }
  return null;
}
function parseJson(text) { try { return JSON.parse(text); } catch { return null; } }
function pyHas(text, name) { return new RegExp(`(?:^|[\\s"'])${name.replace(/[-]/g, '[-_]')}(?:[\\s"'=<>~!\\[]|$)`, 'im').test(text.split('\n').filter(l => !/^\s*#/.test(l)).join('\n')); }

function unitsFrom(source) {
  const units = new Map();
  for (const [file, text] of Object.entries(source.files)) {
    const dir = posixDir(file), base = path.posix.basename(file);
    if (base === 'package.json') {
      const pkg = parseJson(text);
      if (!pkg) { units.set(dir, { dir, stack: 'node', invalid: true }); continue; }
      const deps = { ...pkg.devDependencies, ...pkg.dependencies };
      const front = FRONTEND_DEPS.filter(d => d in deps), back = BACKEND_DEPS.filter(d => d in deps);
      const role = front.length ? 'frontend' : (back.length || pkg.scripts?.start || pkg.main) ? 'backend' : 'unknown';
      units.set(dir, { dir, stack: 'node', role, framework: front[0] || back[0] || null, pkg });
    } else if (/^requirements[^/]*\.txt$|^pyproject\.toml$|^Pipfile$/.test(base) && !units.has(dir)) {
      const fw = PY_FRAMEWORKS.find(n => pyHas(text, n)) || null;
      units.set(dir, { dir, stack: 'python', role: fw ? 'backend' : 'unknown', framework: fw, requirements: base });
    }
  }
  return [...units.values()];
}

function entrypointFor(unit, source, confirmed) {
  const dockerfile = source.files[unit.dir ? `${unit.dir}/Dockerfile` : 'Dockerfile'];
  if (dockerfile !== undefined) {
    const users = [...dockerfile.matchAll(/^\s*USER\s+(\S+)/gmi)].map(m => m[1]);
    const last = users[users.length - 1];
    return { kind: 'repository-dockerfile', nonRootUser: !!last && !/^(root|0)(:|$)/.test(last) };
  }
  if (confirmed) {
    const file = String(confirmed);
    const rel = unit.dir ? `${unit.dir}/${file}` : file;
    const okExt = unit.stack === 'python' ? /^[A-Za-z0-9_][A-Za-z0-9_./-]{0,80}\.py$/ : /^[A-Za-z0-9_][A-Za-z0-9_./-]{0,80}\.(?:js|mjs|cjs)$/;
    if (!okExt.test(file) || file.includes('..') || !source.paths.includes(rel)) throw fail('Confirmed entrypoint is not a file of that component');
    return { kind: unit.stack === 'python' ? 'python' : 'node', file, confirmed: true };
  }
  if (unit.stack === 'python') {
    const found = PY_ENTRYPOINTS.filter(f => source.paths.includes(unit.dir ? `${unit.dir}/${f}` : f));
    if (found.length === 1) return { kind: 'python', file: found[0] };
    return { kind: 'uncertain', candidates: found, reason: found.length ? 'More than one of app.py/main.py/wsgi.py' : 'No app.py, main.py or wsgi.py' };
  }
  if (unit.pkg?.scripts?.start) return { kind: 'npm-start', script: unit.pkg.scripts.start };
  if (typeof unit.pkg?.main === 'string' && source.paths.includes(unit.dir ? `${unit.dir}/${unit.pkg.main}` : unit.pkg.main)) return { kind: 'node', file: unit.pkg.main };
  return { kind: 'uncertain', candidates: [], reason: 'package.json has no start script and no existing main file' };
}

function unitCode(unit, source) {
  const out = [];
  for (const [file, text] of Object.entries(source.code || {})) if (unit.dir === '' ? true : file.startsWith(unit.dir + '/')) out.push([file, text]);
  return out;
}

function portFor(unit, source, entry) {
  const dockerfile = source.files[unit.dir ? `${unit.dir}/Dockerfile` : 'Dockerfile'];
  if (dockerfile) { const m = /^\s*EXPOSE\s+(\d+)/mi.exec(dockerfile); if (m) return { port: Number(m[1]), source: 'Dockerfile EXPOSE' }; }
  if (unit.stack === 'node') { const m = (unit.pkg?.scripts?.start || '').match(/PORT[= ]+(\d+)|--port[= ]+(\d+)/i); if (m) return { port: Number(m[1] || m[2]), source: 'package.json start script' }; }
  const files = entry?.file ? [unit.dir ? `${unit.dir}/${entry.file}` : entry.file] : [];
  if (unit.stack === 'node' && unit.pkg?.main) files.push(unit.dir ? `${unit.dir}/${unit.pkg.main}` : unit.pkg.main);
  for (const f of files) { const p = source.code?.[f] && portFrom(source.code[f]); if (p) return { port: p, source: `${f} listen call` }; }
  for (const [f, text] of unitCode(unit, source)) { const p = portFrom(text); if (p) return { port: p, source: `${f} listen call` }; }
  return { port: unit.stack === 'python' ? 8080 : 3000, source: 'default (not detected)' };
}

// ---- classification ----------------------------------------------------------------------------------------
// Returns what the generator would build. `confirmation` = { architecture, entrypoints: {component: file} }.
function classify(source, confirmation = {}) {
  const analysis = analyze(source.files);
  const base = { analysis, detectedArchitecture: analysis.architecture, confirmationRequired: true, warnings: [] };
  const manual = reason => ({ ...base, result: 'MANUAL_REVIEW', template: null, architecture: analysis.architecture, reason, components: [], database: null });
  const units = unitsFrom(source);
  const unsupportedDb = analysis.databases.filter(d => !(d in SUPPORTED_DATABASES));
  const supportedDb = [...new Set(analysis.databases.filter(d => d in SUPPORTED_DATABASES))];

  if (!units.length) {
    const html = Object.keys(source.files).filter(f => /\.html?$/.test(f));
    if (html.length && analysis.architecture === 'one-tier' && !analysis.databases.length)
      return { ...base, result: 'STATIC_SITE', template: 'static-site', architecture: 'static', reason: 'Only static HTML files; handled by the existing static-site engine (S3 + CloudFront), unchanged.', components: [], database: null };
    return manual('No Python or Node.js application manifest found; only Python and Node.js are supported.');
  }
  if (units.some(u => u.invalid)) return manual('A package.json is not valid JSON.');
  if (['custom', 'unknown'].includes(analysis.architecture)) return manual(`Detected architecture is ${analysis.architecture}; not guessed.`);
  if (unsupportedDb.length) return manual(`Unsupported database ${unsupportedDb.join(', ')}; only PostgreSQL and MySQL are generated.`);
  if (supportedDb.length > 1) return manual('More than one database engine detected.');
  if (units.length > 2) return manual('More than two application manifests; not a standard one/two/three-tier layout.');
  if (units.some(u => u.role === 'unknown')) return manual('An application manifest has no recognised web framework or start command.');

  let architecture, layout;
  const engine = supportedDb[0] ? SUPPORTED_DATABASES[supportedDb[0]] : 'none';
  if (units.length === 1) {
    if (units[0].role === 'frontend' && engine !== 'none') return manual('Frontend-only manifest with a database dependency.');
    architecture = engine === 'none' ? 'one-tier' : 'two-tier';
    layout = { app: units[0] };
  } else {
    const front = units.find(u => u.role === 'frontend'), back = units.find(u => u.role === 'backend');
    if (!front || !back) return manual('Two manifests but not one frontend and one backend.');
    if (engine === 'none') return manual('Frontend and backend without a detected PostgreSQL/MySQL database; not guessed.');
    architecture = 'three-tier';
    layout = { frontend: front, backend: back };
  }

  const confirmedArch = confirmation.architecture;
  if (confirmedArch !== undefined && confirmedArch !== architecture) return manual(`Confirmed architecture ${confirmedArch} differs from the generated ${architecture}; manual review.`);

  const components = [], needs = [];
  for (const [name, unit] of Object.entries(layout)) {
    const entry = entrypointFor(unit, source, confirmation.entrypoints?.[name]);
    if (entry.kind === 'uncertain') needs.push({ component: name, field: 'entrypoint', candidates: entry.candidates, reason: entry.reason });
    if (entry.kind === 'repository-dockerfile' && !entry.nonRootUser) base.warnings.push(`${name}: repository Dockerfile has no non-root USER; Kyverno will reject the pod unless the image runs as non-root.`);
    const { port, source: portSource } = portFor(unit, source, entry);
    if (!(port >= 1024 && port <= 65535)) return manual(`${name}: port ${port} is privileged or invalid; containers run as non-root.`);
    const names = new Set();
    for (const [, text] of unitCode(unit, source)) for (const n of envNamesFrom(text)) names.add(n);
    for (const [f, text] of Object.entries(source.code || {})) if (/\.env\.(example|sample)$/.test(f) && (unit.dir === '' || f.startsWith(unit.dir + '/'))) for (const n of envFileNames(text)) names.add(n);
    const all = [...names].filter(n => ENV_NAME.test(n) && !PLATFORM_ENV.has(n)).sort();
    const dbEnv = engine !== 'none' && name !== 'frontend' ? all.filter(n => DB_ENV.has(n)) : [];
    const secretKeys = all.filter(n => !dbEnv.includes(n)).slice(0, 20);
    if (portSource.startsWith('default')) base.warnings.push(`${name}: port not detected; using default ${port}. Confirm before planning.`);
    components.push({ name, dir: unit.dir, stack: unit.stack, framework: unit.framework, role: unit.role, entrypoint: entry, port, portSource,
      secretKeys, dbEnv, usesDatabase: engine !== 'none' && name !== 'frontend', public: name !== 'backend',
      dockerfile: entry.kind === 'repository-dockerfile' ? 'repository' : 'generated' });
  }
  const result = needs.length ? 'CONFIRM_ENTRYPOINT' : 'CONTAINER';
  return { ...base, result, template: 'eks-project', architecture, reason: `${architecture}: ${components.map(c => `${c.name} (${c.stack}${c.framework ? '/' + c.framework : ''})`).join(', ')}${engine !== 'none' ? ` + RDS ${engine}` : ''}`,
    components, database: engine === 'none' ? null : { engine, name: 'app' }, needsConfirmation: needs };
}

// ---- tfvars -------------------------------------------------------------------------------------------------
function assertProject(projectId) {
  if (!Number.isSafeInteger(projectId) || projectId < 1) throw fail('Invalid project');
  if (PROTECTED_PROJECTS.includes(projectId)) throw fail('Existing/protected project infrastructure is read-only', 409);
}
function buildTfvars(projectId, classification, { clusterName = process.env.EKS_CLUSTER_NAME || DEFAULT_CLUSTER } = {}) {
  assertProject(projectId);
  if (classification.result !== 'CONTAINER' || classification.template !== 'eks-project') throw fail('Only a confirmed container classification can be planned', 409);
  if (!/^cloudsentinel-[a-z0-9-]{1,30}$/.test(clusterName)) throw fail('Invalid cluster name');
  const components = {};
  for (const c of classification.components) {
    if (!COMPONENT_NAMES.includes(c.name)) throw fail('Invalid component');
    if (!Number.isInteger(c.port) || c.port < 1024 || c.port > 65535) throw fail('Invalid port');
    if (!Array.isArray(c.secretKeys) || c.secretKeys.length > 20 || c.secretKeys.some(n => !ENV_NAME.test(n))) throw fail('Invalid environment variable name');
    components[c.name] = { port: c.port, env_names: [...c.secretKeys] };
  }
  const keys = Object.keys(components).sort().join(',');
  if (!['app', 'backend,frontend'].includes(keys)) throw fail('Invalid component layout');
  const db = classification.database;
  if (db && (!['postgres', 'mysql'].includes(db.engine) || !/^[a-z][a-z0-9_]{0,30}$/.test(db.name))) throw fail('Invalid database');
  if (keys === 'backend,frontend' && !db) throw fail('Three-tier layout requires a database');
  return { project_id: projectId, environment: 'development', cluster_name: clusterName, components, database: db ? { engine: db.engine, name: db.name } : { engine: 'none', name: 'app' } };
}

// Copies the fixed templates into `jobDir` (same relative layout as the repository) and writes the tfvars.
// Returns the directory to run terraform in and a hash over the exact template bytes + tfvars.
async function generate(jobDir, tfvars, { repoRoot = REPO_ROOT } = {}) {
  const hashes = [];
  for (const rel of TEMPLATE_DIRS) {
    const src = path.join(repoRoot, rel), dst = path.join(jobDir, rel);
    await fs.mkdir(dst, { recursive: true, mode: 0o700 });
    for (const name of (await fs.readdir(src)).sort()) {
      if (!/^(?:[a-z_]+\.tf|\.terraform\.lock\.hcl)$/.test(name)) continue;
      const data = await fs.readFile(path.join(src, name));
      hashes.push([`${rel}/${name}`, sha256(data)]);
      await fs.writeFile(path.join(dst, name), data, { mode: 0o600, flag: 'wx' });
    }
  }
  const root = path.join(jobDir, TEMPLATE_DIRS[0]);
  const body = JSON.stringify(tfvars, null, 2) + '\n';
  await fs.writeFile(path.join(root, 'terraform.tfvars.json'), body, { mode: 0o600, flag: 'wx' });
  return { root, configurationHash: sha256(JSON.stringify({ hashes, tfvars })) };
}

// ---- Dockerfile ---------------------------------------------------------------------------------------------
// Hardened, non-root Dockerfile for a component without one. Refuses when the entrypoint is uncertain.
function generateDockerfile(component, { hasLockfile = false } = {}) {
  const e = component.entrypoint;
  if (!e || e.kind === 'uncertain') throw fail('Confirm entrypoint before generating a Dockerfile', 409);
  if (e.kind === 'repository-dockerfile') throw fail('The repository already has a Dockerfile', 409);
  const port = component.port;
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw fail('Invalid port');
  const file = e.file && JSON.stringify(e.file);
  if (component.stack === 'python') {
    return `# Generated by CloudSentinel for EKS: pinned base, non-root UID 10001, no build tools at runtime.
FROM ${BASE_IMAGES.python}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PORT=${port}
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=10001:10001 . .
USER 10001:10001
EXPOSE ${port}
CMD ["python", ${file}]
`;
  }
  if (component.stack === 'node') {
    const cmd = e.kind === 'npm-start' ? '["npm", "start"]' : `["node", ${file}]`;
    return `# Generated by CloudSentinel for EKS: pinned base, non-root UID 10001, production dependencies only.
FROM ${BASE_IMAGES.node}
ENV NODE_ENV=production PORT=${port} NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_CACHE=/tmp/.npm
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app -s /sbin/nologin app
WORKDIR /app
COPY package*.json ./
RUN ${hasLockfile ? 'npm ci --omit=dev' : 'npm install --omit=dev --no-audit --no-fund'}
COPY --chown=10001:10001 . .
USER 10001:10001
EXPOSE ${port}
CMD ${cmd}
`;
  }
  throw fail('Only Python and Node.js components are supported');
}

// ---- plan allowlist -----------------------------------------------------------------------------------------
const WORKLOAD_TYPES = { aws_ecr_repository: 'this', aws_secretsmanager_secret: 'this', aws_cloudwatch_log_group: 'this', aws_iam_role: 'irsa', aws_iam_role_policy: 'irsa' };
const DATABASE_TYPES = { aws_db_subnet_group: 'this', aws_security_group: 'this', aws_db_instance: 'this' };
const TAGGED = new Set(['aws_ecr_repository', 'aws_secretsmanager_secret', 'aws_cloudwatch_log_group', 'aws_iam_role', 'aws_db_subnet_group', 'aws_security_group', 'aws_db_instance']);
const IRSA_ACTIONS = new Set(['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret', 'logs:CreateLogStream', 'logs:PutLogEvents']);
const reject = code => { throw fail(`Plan rejected: ${code}`, 409); };
const list = v => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
function parsePolicy(text) { const p = typeof text === 'string' ? parseJson(text) : null; if (!p || !Array.isArray(p.Statement) && typeof p.Statement !== 'object') reject('IAM_POLICY_UNREADABLE'); return list(p.Statement); }

// expected = { projectId, components: ['app'] | ['frontend','backend'], database: 'postgres'|'mysql'|null }
function inspectPlan(plan, expected) {
  const { projectId } = expected;
  assertProject(projectId);
  if (!plan || plan.errored || !Array.isArray(plan.resource_changes)) reject('MALFORMED_PLAN');
  const provider = plan.configuration?.provider_config?.aws?.expressions;
  if (provider?.region?.constant_value !== REGION || JSON.stringify(provider?.allowed_account_ids?.constant_value) !== JSON.stringify([ACCOUNT])) reject('ACCOUNT_OR_REGION_NOT_PINNED');
  const comps = [...expected.components].sort();
  if (!['app', 'backend,frontend'].includes(comps.join(','))) reject('UNEXPECTED_COMPONENTS');
  const dbEngine = expected.database || null;
  if (dbEngine && !['postgres', 'mysql'].includes(dbEngine)) reject('UNSUPPORTED_DATABASE');

  const want = new Map();
  for (const c of comps) for (const [type, name] of Object.entries(WORKLOAD_TYPES)) want.set(`module.workload["${c}"].${type}.${name}`, { type, component: c });
  if (dbEngine) for (const [type, name] of Object.entries(DATABASE_TYPES)) want.set(`module.database[0].${type}.${name}`, { type });

  const managed = [];
  for (const r of plan.resource_changes) {
    const actions = JSON.stringify(r.change?.actions || []);
    if (r.mode === 'data') { if (!['["read"]', '["no-op"]'].includes(actions)) reject('DATA_SOURCE_ACTION'); continue; }
    if (r.mode !== 'managed') reject('UNKNOWN_MODE');
    if (actions !== '["create"]') reject('NON_CREATE_ACTION');
    const w = want.get(r.address);
    if (!w || w.type !== r.type) reject(`UNEXPECTED_RESOURCE ${String(r.type).slice(0, 60)}`);
    managed.push(r);
  }
  if (managed.length !== want.size || new Set(managed.map(r => r.address)).size !== want.size) reject('RESOURCE_COUNT_MISMATCH');

  const sgPort = dbEngine === 'mysql' ? 3306 : 5432;
  for (const r of managed) {
    const a = r.change.after || {}, w = want.get(r.address), c = w.component;
    if (TAGGED.has(r.type)) {
      const t = a.tags_all || {};
      if (t.Project !== 'cloudsentinel' || t.ProjectId !== String(projectId) || t.Module !== MODULE_TAG || t.Environment !== 'development' || t.ManagedBy !== 'Terraform') reject('TAGS_MISSING_OR_WRONG');
    }
    switch (r.type) {
      case 'aws_ecr_repository':
        if (a.name !== `cloudsentinel/p-${projectId}-${c}` || a.image_tag_mutability !== 'IMMUTABLE' || a.image_scanning_configuration?.[0]?.scan_on_push !== true) reject('ECR_SETTINGS');
        break;
      case 'aws_secretsmanager_secret':
        if (a.name !== `cloudsentinel/p-${projectId}/${c}` || a.recovery_window_in_days !== 0) reject('SECRET_SETTINGS');
        break;
      case 'aws_cloudwatch_log_group':
        if (a.name !== `/cloudsentinel/projects/${projectId}/${c}` || !(a.retention_in_days > 0 && a.retention_in_days <= 14)) reject('LOG_GROUP_SETTINGS');
        break;
      case 'aws_iam_role': {
        if (a.name !== `cloudsentinel-p${projectId}-${c}-irsa`) reject('IAM_ROLE_NAME');
        if (list(a.managed_policy_arns).length) reject('IAM_ROLE_POLICIES');
        if (a.permissions_boundary !== `arn:aws:iam::${ACCOUNT}:policy/cloudsentinel-workload-boundary`) reject('IAM_PERMISSIONS_BOUNDARY');
        const st = parsePolicy(a.assume_role_policy);
        if (st.length !== 1) reject('IAM_TRUST');
        const s = st[0], fed = list(s.Principal?.Federated), cond = s.Condition?.StringEquals || {};
        const subKey = Object.keys(cond).find(k => k.endsWith(':sub'));
        if (s.Effect !== 'Allow' || JSON.stringify(list(s.Action)) !== '["sts:AssumeRoleWithWebIdentity"]' || fed.length !== 1 ||
          !/^arn:aws:iam::229032674007:oidc-provider\/oidc\.eks\.ap-south-1\.amazonaws\.com\/id\/[A-F0-9]{32}$/.test(fed[0]) ||
          !subKey || JSON.stringify(list(cond[subKey])) !== JSON.stringify([`system:serviceaccount:cloudsentinel-p-${projectId}:p${projectId}-${c}`])) reject('IAM_TRUST');
        break;
      }
      case 'aws_iam_role_policy': {
        const secretPrefix = `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:cloudsentinel/p-${projectId}/${c}-`;
        const logArn = `arn:aws:logs:${REGION}:${ACCOUNT}:log-group:/cloudsentinel/projects/${projectId}/${c}:log-stream:*`;
        for (const s of parsePolicy(a.policy)) {
          if (s.Effect !== 'Allow' || s.NotAction || s.NotResource) reject('IAM_POLICY_SHAPE');
          for (const act of list(s.Action)) if (!IRSA_ACTIONS.has(act)) reject('IAM_ACTION_NOT_ALLOWED');
          for (const res of list(s.Resource)) if (res !== logArn && !(res.startsWith(secretPrefix) && /^-\?{6}$|^-[A-Za-z0-9]{6}$/.test(res.slice(secretPrefix.length - 1)))) reject('IAM_RESOURCE_NOT_ALLOWED');
        }
        break;
      }
      case 'aws_db_instance':
        if (a.identifier !== `cloudsentinel-p${projectId}-db` || a.engine !== dbEngine || a.instance_class !== 'db.t3.micro') reject('RDS_IDENTITY');
        if (a.publicly_accessible !== false) reject('PUBLIC_RDS');
        if (a.storage_encrypted !== true || a.manage_master_user_password !== true || (a.password !== undefined && a.password !== null) || a.multi_az !== false || !(a.allocated_storage <= 20)) reject('RDS_SETTINGS');
        break;
      case 'aws_security_group':
        if (a.name !== `cloudsentinel-p${projectId}-db`) reject('SG_NAME');
        if (list(a.egress).length) reject('SG_EGRESS');
        if (!list(a.ingress).length) reject('SG_INGRESS');
        for (const i of list(a.ingress)) {
          if (list(i.cidr_blocks).length || list(i.ipv6_cidr_blocks).length || list(i.prefix_list_ids).length || i.self) reject('DATABASE_OPEN_TO_NETWORK');
          if (i.from_port !== sgPort || i.to_port !== sgPort || i.protocol !== 'tcp' || list(i.security_groups).length !== 1) reject('SG_INGRESS_SCOPE');
        }
        break;
      case 'aws_db_subnet_group':
        if (a.name !== `cloudsentinel-p${projectId}-db`) reject('SUBNET_GROUP_NAME');
        break;
      default: reject('UNEXPECTED_RESOURCE');
    }
  }
  return managed.map(r => ({ address: r.address, type: r.type, actions: r.change.actions, projectId }));
}

// Destroy plans may only delete exactly the addresses that the approved apply created.
function inspectDestroyPlan(plan, { projectId, addresses }) {
  assertProject(projectId);
  if (!plan || plan.errored || !Array.isArray(plan.resource_changes) || !Array.isArray(addresses) || !addresses.length) reject('MALFORMED_DESTROY_PLAN');
  const allowed = new Set(addresses);
  const managed = plan.resource_changes.filter(r => r.mode === 'managed');
  for (const r of plan.resource_changes) if (r.mode === 'data' && !['["read"]', '["no-op"]'].includes(JSON.stringify(r.change?.actions || []))) reject('DATA_SOURCE_ACTION');
  for (const r of managed) {
    if (JSON.stringify(r.change?.actions) !== '["delete"]') reject('NON_DELETE_ACTION');
    if (!allowed.has(r.address)) reject('OUT_OF_SCOPE_DELETE');
  }
  if (managed.length !== allowed.size) reject('DESTROY_SCOPE_MISMATCH');
  return managed.map(r => ({ address: r.address, type: r.type, actions: r.change.actions, projectId }));
}

module.exports = {
  ACCOUNT, REGION, PROTECTED_PROJECTS, MODULE_TAG, DEFAULT_CLUSTER, ECR_HOST, BASE_IMAGES, TEMPLATE_DIRS, REPO_ROOT,
  localSource, classify, buildTfvars, generate, generateDockerfile, inspectPlan, inspectDestroyPlan, assertProject,
  envNamesFrom, portFrom, MANIFEST, CODE, SKIP_DIR,
};
