#!/usr/bin/env node
'use strict';
// CloudSentinel infrastructure CLI for per-project EKS workloads (Module 8). Same engine and gates as the API.
//
//   node scripts/infra-cli.js <command> (--dir <checkout> --project-id <n> | --project <n> --user <id>) [options]
//
// Commands:
//   analyze                         detect languages, frameworks, databases, ports, architecture
//   confirm [--architecture A] [--entrypoint component=file ...]
//   plan                            generate, fmt, Trivy (no CRITICAL), init, validate, plan, allowlist check
//   approve --hash <sha256> [--kind destroy]
//   apply | destroy-plan | destroy  gated: INFRA_APPLY_ENABLED=true, kill switch off, approved plan hash
//   status | gate
//   artifacts --tag <tag> --out <dir>   write generated Dockerfile(s) and manifests after apply
//
// --dir mode reads a local checkout (bounded, read-only) and needs no database; --project mode reads the registered
// GitHub repository and checks ownership in the database (BACKEND_ENV_FILE or backend/.env).
// Output never contains credentials or secret values. AWS profile: INFRA_AWS_PROFILE (default cloudsentinel-dev).

const path = require('node:path');
const fs = require('node:fs/promises');
const os = require('node:os');
const backend = path.resolve(__dirname, '../backend');
const W = require(path.join(backend, 'services/eksWorkload'));
const { WorkloadInfrastructure, applyGate } = require(path.join(backend, 'services/eksWorkloadEngine'));

function parse(argv) {
  const [cmd, ...rest] = argv, opts = { entrypoint: [] };
  for (let i = 0; i < rest.length; i++) {
    const k = rest[i];
    if (!k.startsWith('--')) throw new Error(`Unexpected argument ${k}`);
    const key = k.slice(2), v = rest[i + 1];
    if (v === undefined || v.startsWith('--')) throw new Error(`Missing value for ${k}`);
    i++;
    if (key === 'entrypoint') opts.entrypoint.push(v); else opts[key] = v;
  }
  return { cmd, opts };
}

async function main() {
  const { cmd, opts } = parse(process.argv.slice(2));
  const allowed = ['analyze', 'confirm', 'plan', 'approve', 'apply', 'destroy-plan', 'destroy', 'status', 'gate', 'artifacts'];
  if (!allowed.includes(cmd)) throw new Error(`usage: infra-cli.js <${allowed.join('|')}> ...`);
  let project, userId, source;
  if (opts.dir) {
    const id = Number(opts['project-id']);
    if (!Number.isSafeInteger(id) || id < 1) throw new Error('--project-id <n> is required with --dir');
    const dir = path.resolve(opts.dir);
    project = { id, user_id: `cli:${os.userInfo().username}` };
    userId = project.user_id;
    source = () => W.localSource(dir);
  } else if (opts.project) {
    require('dotenv').config({ path: process.env.BACKEND_ENV_FILE || path.join(backend, '.env'), quiet: true });
    const pool = require(path.join(backend, 'db'));
    const { ownedProject, repositoryFiles } = require(path.join(backend, 'services/infrastructurePlanning'));
    userId = Number(opts.user);
    if (!Number.isSafeInteger(userId)) throw new Error('--user <id> is required with --project');
    try { project = await ownedProject(pool, userId, opts.project); } finally { await pool.end().catch(() => {}); }
    source = p => repositoryFiles(p, { withCode: true });
  } else throw new Error('Give --dir <checkout> --project-id <n>, or --project <n> --user <id>');

  const engine = new WorkloadInfrastructure({ source });
  W.assertProject(project.id);
  let record;
  switch (cmd) {
    case 'gate': return print({ projectId: project.id, ...applyGate(engine.root) });
    case 'status': record = await engine.get(project.id); break;
    case 'analyze': record = await engine.analyze(project, userId); break;
    case 'confirm': {
      const entrypoints = {};
      for (const e of opts.entrypoint) { const m = /^(app|frontend|backend)=(.+)$/.exec(e); if (!m) throw new Error('--entrypoint component=file'); entrypoints[m[1]] = m[2]; }
      const current = await engine.get(project.id);
      record = await engine.confirm(project, userId, { architecture: opts.architecture || current.classification?.architecture, entrypoints }); break;
    }
    case 'plan': record = await engine.plan(project, userId); break;
    case 'approve': record = await engine.approve(project, userId, { hash: opts.hash, kind: opts.kind === 'destroy' ? 'destroy' : 'apply' }); break;
    case 'apply': record = await engine.apply(project, userId); break;
    case 'destroy-plan': record = await engine.destroyPlan(project, userId); break;
    case 'destroy': record = await engine.destroy(project, userId); break;
    case 'artifacts': {
      if (!opts.tag || !opts.out) throw new Error('--tag <tag> --out <dir> required');
      const out = path.resolve(opts.out);
      await fs.mkdir(out, { recursive: true });
      const items = await engine.artifacts(project, { tag: opts.tag });
      for (const a of items) {
        await fs.writeFile(path.join(out, `${a.component}.yaml`), a.manifests.yaml);
        if (a.dockerfile) await fs.writeFile(path.join(out, `${a.component}.Dockerfile`), a.dockerfile);
      }
      return print({ projectId: project.id, written: items.map(a => ({ component: a.component, dir: a.dir || '.', manifests: `${a.component}.yaml`, dockerfile: a.dockerfile ? `${a.component}.Dockerfile` : 'repository' })) });
    }
  }
  print(engine.publicRecord(record));
}

function print(v) { process.stdout.write(JSON.stringify(v, null, 2) + '\n'); }

main().catch(e => { process.stderr.write(`infra-cli: ${e.safe ? e.message : e.message || 'failed'}\n`); process.exit(1); });
