'use strict';
// Execution report helpers (Module 12): source revision, per-stage timeline, engine versions, the gate rules in
// force, the dependency inventory split and a content-derived report ID. Pure functions; routes/reports.js does I/O.
const crypto = require('node:crypto');
const vulnerabilityGate = require('./vulnerabilityGate');
const secretScan = require('./secretScan');

// pg returns Date objects; Date.parse(Date) would go through toString() and drop the milliseconds.
const time = v => (v === null || v === undefined || v === '' ? NaN : v instanceof Date ? v.getTime() : Date.parse(v));
const ms = (start, end) => {
  const s = time(start), e = time(end);
  return Number.isFinite(s) && Number.isFinite(e) && e >= s ? e - s : null;
};

// Repository URL without any userinfo (a token embedded in a clone URL must never reach a report).
function repositoryUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(String(url));
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    u.username = ''; u.password = ''; u.search = ''; u.hash = '';
    return u.toString().replace(/\.git\/?$/, '').replace(/\/$/, '');
  } catch { return null; }
}

// Source revision: provenance mode (pipeline_source_revisions) wins; otherwise the webhook-recorded columns
// (migration 026). Manual runs clone at run time and record no commit, which the report states instead of guessing.
function source(execution, revision = null) {
  const repository = repositoryUrl(revision?.repository_identity || execution?.repo_url);
  if (revision) return { repository, branch: revision.branch || null, commit: revision.commit_sha || null, message: execution?.source_commit_message || null, recordedBy: 'provenance' };
  if (execution?.source_commit) return { repository, branch: execution.source_branch || null, commit: execution.source_commit, message: execution.source_commit_message || null, recordedBy: 'webhook' };
  return {
    repository, branch: execution?.source_branch || null, commit: null, message: null, recordedBy: null,
    note: execution?.triggered_by === 'webhook'
      ? 'Commit not recorded for this execution (webhook runs record it from migration 026 on).'
      : 'Commit not recorded: manual runs clone the repository at run time and do not store the revision.',
  };
}

const completedList = execution => String(execution?.stages_completed || '').split(',').map(s => s.trim()).filter(Boolean);

function scanResult(name, scan, completed, execution) {
  if (completed.includes(name)) return 'PASSED';
  if (!scan) return 'NOT_RUN';
  if (scan.status === 'COMPLETED') return execution?.status === 'RUNNING' ? 'RUNNING' : 'BLOCKED'; // scan finished, gate did not pass
  if (scan.status === 'BLOCKED') return 'BLOCKED';
  if (['RUNNING', 'PENDING', 'TRIGGERED'].includes(scan.status)) return 'RUNNING';
  return 'FAILED';
}

// One row per stage in pipeline order. Deploy has no stored start time; its duration is measured from the end of
// the previous recorded stage (image scan, else IaC) and flagged as derived.
function stages(execution, scans = {}, deployment = null) {
  const completed = completedList(execution);
  const row = (stage, scan, result, extra = {}) => ({ stage, result, status: scan?.status || null, scanId: scan?.id || null, startedAt: scan?.started_at || null, completedAt: scan?.completed_at || null, durationMs: ms(scan?.started_at, scan?.completed_at), ...extra });
  const out = [
    row('SAST', scans.sast, scanResult('SAST', scans.sast, completed, execution)),
    row('Dependency', scans.dependency, scanResult('Dependency', scans.dependency, completed, execution)),
    row('IaC', scans.iac, scanResult('IaC', scans.iac, completed, execution)),
    row('Container image', scans.image, !scans.image ? 'NOT_RUN' : scans.image.status === 'COMPLETED' ? 'PASSED' : scans.image.status === 'BLOCKED' ? 'BLOCKED' : scans.image.status === 'RUNNING' ? 'RUNNING' : 'FAILED'),
  ];
  const deployStart = scans.image?.completed_at || scans.iac?.completed_at || null;
  out.push({ stage: 'Deploy', result: completed.includes('Deploy') ? 'PASSED' : deployment ? (deployment.status === 'SUCCESS' ? 'PASSED' : 'FAILED') : 'NOT_RUN', status: deployment?.status || null, scanId: deployment?.id || null, startedAt: deployment ? deployStart : null, completedAt: deployment?.deployed_at || null, durationMs: deployment ? ms(deployStart, deployment.deployed_at) : null, durationDerived: !!deployment });
  out.push(row('DAST', scans.dast, scanResult('DAST', scans.dast, completed, execution)));
  const active = scans.activeDast;
  if (active && active.status !== 'UNAVAILABLE') out.push({ stage: 'Active DAST', result: String(active.status || '').startsWith('COMPLETED') ? 'PASSED' : active.status === 'BLOCKED' ? 'BLOCKED' : 'FAILED', status: active.status || null, scanId: null, startedAt: null, completedAt: active.created_at || null, durationMs: Number.isFinite(Number(active.duration_ms)) ? Number(active.duration_ms) : null });
  return out;
}

const shortSha = v => (typeof v === 'string' && /^[a-f0-9]{64}$/.test(v) ? v.slice(0, 12) : null);

function mlEngine(scan, kind) {
  if (!scan) return null;
  const p = scan.tool_provenance && typeof scan.tool_provenance === 'object' ? scan.tool_provenance : null;
  if (scan.scan_engine === 'ml' || p?.engine === 'ml') {
    return { engine: 'ml', name: p?.model?.name || null, version: p?.model?.version || null, modelSha256: shortSha(p?.model?.sha256), status: p?.model?.status || null, tool: p?.tool ? String(p.tool).slice(0, 200) : null };
  }
  return { engine: scan.scan_engine || 'legacy', name: kind === 'SAST' ? 'SonarQube (legacy)' : 'OWASP ZAP (legacy)', version: null, tool: p?.tool ? String(p.tool).slice(0, 200) : null };
}

function trivyVersion(sbomHead) {
  const m = String(sbomHead || '').match(/"name"\s*:\s*"trivy"\s*,\s*"version"\s*:\s*"([0-9A-Za-z.+-]{1,40})"/);
  return m ? m[1] : null;
}

// Engine name and version per stage, as recorded with the scan. Trivy records its version only in the dependency
// SBOM; the IaC and image stages run the same binary but store no version, which is stated rather than assumed.
function engines(scans = {}, { sbomHead = null } = {}) {
  const trivy = trivyVersion(sbomHead);
  const unrecorded = trivy ? `not recorded for this stage (the dependency stage of this run used Trivy ${trivy})` : 'not recorded for this stage';
  return {
    SAST: mlEngine(scans.sast, 'SAST'),
    Dependency: scans.dependency ? { engine: 'trivy', name: 'Trivy fs (vulnerabilities + CycloneDX SBOM)', version: trivy, versionSource: trivy ? 'SBOM metadata.tools' : null } : null,
    IaC: scans.iac ? { engine: 'trivy', name: `Trivy config${scans.iac.adapter ? ` (${scans.iac.adapter})` : ''}`, version: null, versionNote: unrecorded } : null,
    'Container image': scans.image ? { engine: 'trivy', name: 'Trivy image', version: null, versionNote: unrecorded } : null,
    DAST: mlEngine(scans.dast, 'DAST'),
  };
}

function describeGate(kind, env) {
  try { return { rule: vulnerabilityGate.describe(vulnerabilityGate.policy(kind, env)), valid: true }; }
  catch { return { rule: 'Gate configuration is invalid; the stage fails closed (blocks).', valid: false }; }
}

// The rules in force on this server when the report is generated (gates read the environment at run time).
function gateRules(env = process.env) {
  const dep = describeGate('DEPENDENCY', env), img = describeGate('IMAGE', env);
  return {
    note: 'Current server configuration at report generation time.',
    rules: [
      { stage: 'SAST', blocks: 'CRITICAL or HIGH security vulnerabilities, unreviewed security hotspots and unclassified findings', why: 'Exploitable code flaws must be fixed or reviewed before deployment; maintainability findings (code smells, bugs) do not block.' },
      { stage: 'Dependency', blocks: dep.rule, why: 'Known vulnerable packages with an available upgrade must be upgraded; CRITICAL blocks even without a fix.', config: 'DEPENDENCY_GATE_SEVERITIES / DEPENDENCY_GATE_UNFIXED_SEVERITIES', valid: dep.valid },
      { stage: 'IaC', blocks: `any CRITICAL misconfiguration${secretScan.enabled(env) ? ', including committed secrets (Trivy secret scan)' : ' (committed-secret scan disabled by IAC_SECRET_SCAN=off)'}`, why: 'Critical infrastructure misconfigurations and leaked credentials are not deployable.' },
      { stage: 'Container image', blocks: img.rule, why: 'The built image must not ship known vulnerable OS or language packages that can be fixed.', config: 'IMAGE_GATE_SEVERITIES / IMAGE_GATE_UNFIXED_SEVERITIES', valid: img.valid },
      { stage: 'Deploy', blocks: 'Kubernetes server-side dry-run (Kyverno admission) rejections and failed rollouts', why: 'Workloads must satisfy the cluster admission policies.' },
      { stage: 'DAST', blocks: 'scan failure only; passive DAST findings are reported, not blocking', why: 'Baseline DAST confirms the deployed app was scanned; findings feed governance review.' },
    ],
  };
}

// sbom_components holds the whole package inventory. Rows Trivy reported with no vulnerability are stored with
// severity NONE and no CVE: they are clean packages, not findings.
function splitDependency(rows = []) {
  const findings = [], clean = [];
  for (const r of rows) (String(r.severity || '').toUpperCase() === 'NONE' && !r.cve_id ? clean : findings).push(r);
  return { findings, clean: clean.map(r => ({ pkg_name: r.pkg_name, pkg_version: r.pkg_version })) };
}

// SAST limitation text: a clean completed scan is "No findings", not a missing-details warning.
function sastNote(scan, findings) {
  if (!scan || findings.length) return null;
  if (scan.status === 'COMPLETED' && Number(scan.total_issues || 0) === 0) return 'No findings';
  return 'No execution-linked SAST details are available; legacy scan_results are intentionally excluded.';
}

function canonical(v) {
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => [k, canonical(v[k])]));
  return v;
}

// Same evidence -> same ID; any change to the stored evidence gives a new ID. generatedAt is not part of it.
function reportId(executionId, body) {
  return `CSR-${executionId}-${crypto.createHash('sha256').update(JSON.stringify(canonical(body))).digest('hex').slice(0, 12)}`;
}

// Kubernetes admission evidence recorded with this execution's deployment (deployment_history.policy_validation).
function admission(deployment) {
  const v = deployment?.policy_validation;
  if (!v || typeof v !== 'object') return deployment ? { status: 'not_recorded' } : null;
  return { status: v.passed ? 'passed' : 'failed', engine: v.engine || null, namespace: v.namespace || null, checkedAt: v.checkedAt || null, violations: Array.isArray(v.violations) ? v.violations.length : null };
}

// Branch, commit and head-commit message from a GitHub push payload, validated before storage (migration 026).
function pushSource(body) {
  const ref = typeof body?.ref === 'string' && body.ref.startsWith('refs/heads/') ? body.ref.slice('refs/heads/'.length) : null;
  const branch = ref && require('./pipelineProvenance').validBranch(ref) ? ref : null;
  const commit = typeof body?.after === 'string' && /^[a-f0-9]{40}$/.test(body.after) && !/^0{40}$/.test(body.after) ? body.after : null;
  const raw = typeof body?.head_commit?.message === 'string' ? body.head_commit.message : '';
  const message = raw.split('\n')[0].replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 500) || null;
  return { branch, commit, message: commit ? message : null };
}

module.exports = { pushSource, ms, repositoryUrl, source, stages, engines, trivyVersion, gateRules, splitDependency, sastNote, reportId, admission, canonical };
