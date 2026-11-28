// Module 12 execution report: source revision, stage timeline, engine versions, gate rules, dependency
// inventory split (execution 123: Flask-WTF / waitress were clean SBOM rows shown as UNKNOWN "Finding"), report ID.
const assert = require('node:assert/strict');
const test = require('node:test');
const R = require('../services/executionReport');

const sha = 'a'.repeat(40);

test('repository URL never carries credentials, query or .git suffix', () => {
  assert.equal(R.repositoryUrl('https://user:tok123@github.com/o/r.git?x=1'), 'https://github.com/o/r');
  assert.equal(R.repositoryUrl('git@github.com:o/r.git'), null);
  assert.equal(R.repositoryUrl(null), null);
});

test('source: provenance row, webhook columns, or an honest "not recorded" note', () => {
  const ex = { repo_url: 'https://github.com/o/r.git', triggered_by: 'webhook' };
  assert.deepEqual(R.source(ex, { branch: 'main', commit_sha: sha, repository_identity: 'https://github.com/o/r' }), { repository: 'https://github.com/o/r', branch: 'main', commit: sha, message: null, recordedBy: 'provenance' });
  const hook = R.source({ ...ex, source_branch: 'main', source_commit: sha, source_commit_message: 'fix: x' });
  assert.equal(hook.commit, sha); assert.equal(hook.message, 'fix: x'); assert.equal(hook.recordedBy, 'webhook');
  assert.match(R.source(ex).note, /webhook runs record it from migration 026/);
  assert.match(R.source({ ...ex, triggered_by: 'manual' }).note, /manual runs/);
});

test('push payload: branch, commit and first message line are validated and bounded', () => {
  assert.deepEqual(R.pushSource({ ref: 'refs/heads/main', after: sha, head_commit: { message: 'feat: one\n\nbody' } }), { branch: 'main', commit: sha, message: 'feat: one' });
  assert.deepEqual(R.pushSource({ ref: 'refs/tags/v1', after: '0'.repeat(40) }), { branch: null, commit: null, message: null });
  assert.equal(R.pushSource({ ref: 'refs/heads/a..b', after: 'xyz' }).branch, null);
  assert.equal(R.pushSource({ ref: 'refs/heads/m', after: sha, head_commit: { message: 'x'.repeat(900) } }).message.length, 500);
  assert.equal(R.pushSource({ ref: 'refs/heads/m', after: sha, head_commit: { message: 'a\u0007b' } }).message, 'a b');
});

const e123 = { id: 123, status: 'COMPLETED', stages_completed: 'SAST, Dependency, IaC, Deploy, DAST', started_at: '2026-11-26T20:10:27.485Z', completed_at: '2026-11-26T20:11:02.813Z' };
const scans123 = {
  sast: { id: 157, status: 'COMPLETED', total_issues: 0, started_at: '2026-11-26T20:10:27.504Z', completed_at: '2026-11-26T20:10:34.075Z', scan_engine: 'ml', tool_provenance: { engine: 'ml', tool: 'ml-sast-v3-ensemble 3.0.0', model: { name: 'ml-sast-v3-ensemble', version: '3.0.0', sha256: 'f'.repeat(64), status: 'trained' } } },
  dependency: { id: 84, status: 'COMPLETED', started_at: '2026-11-26T20:10:34.094Z', completed_at: '2026-11-26T20:10:37.080Z' },
  iac: { id: 82, status: 'COMPLETED', adapter: 'trivy-config-v1', started_at: '2026-11-26T20:10:37.094Z', completed_at: '2026-11-26T20:10:39.820Z' },
  image: { id: 50, status: 'COMPLETED', started_at: '2026-11-26T20:10:42.783Z', completed_at: '2026-11-26T20:10:44.211Z' },
  dast: { id: 53, status: 'COMPLETED', started_at: '2026-11-26T20:11:02.675Z', completed_at: '2026-11-26T20:11:02.803Z', scan_engine: 'ml', tool_provenance: { engine: 'ml', model: { name: 'ml-dast-lr', version: '4.0.0' } } },
};
const deploy123 = { id: 65, status: 'SUCCESS', deployed_at: '2026-11-26T20:11:02.653Z' };

test('stages: result and duration per stage in pipeline order; Deploy duration is derived', () => {
  const s = R.stages(e123, scans123, deploy123);
  assert.deepEqual(s.map(x => x.stage), ['SAST', 'Dependency', 'IaC', 'Container image', 'Deploy', 'DAST']);
  assert.ok(s.every(x => x.result === 'PASSED'));
  assert.equal(s[0].durationMs, 6571);
  assert.equal(R.ms(new Date('2026-11-26T20:11:02.675Z'), new Date('2026-11-26T20:11:02.803Z')), 128); // pg Date objects keep ms
  assert.equal(s[4].durationMs, 18442); assert.equal(s[4].durationDerived, true);
  const blocked = R.stages({ ...e123, status: 'STAGE_FAILED', stages_completed: 'SAST' }, { sast: scans123.sast, dependency: scans123.dependency }, null);
  assert.equal(blocked[1].result, 'BLOCKED'); assert.equal(blocked[2].result, 'NOT_RUN'); assert.equal(blocked[4].result, 'NOT_RUN');
  assert.equal(R.stages(e123, { ...scans123, image: { ...scans123.image, status: 'BLOCKED' } }, deploy123)[3].result, 'BLOCKED');
});

test('engines: ML model name/version per stage; Trivy version only where the scan recorded it', () => {
  const sbomHead = '{"metadata":{"tools":{"components":[{"type":"application","group":"aquasecurity","name": "trivy",\n "version": "0.52.2"}]}}';
  const e = R.engines(scans123, { sbomHead });
  assert.deepEqual([e.SAST.name, e.SAST.version, e.SAST.modelSha256], ['ml-sast-v3-ensemble', '3.0.0', 'ffffffffffff']);
  assert.deepEqual([e.DAST.name, e.DAST.version], ['ml-dast-lr', '4.0.0']);
  assert.equal(e.Dependency.version, '0.52.2');
  assert.equal(e.IaC.version, null); assert.match(e.IaC.versionNote, /dependency stage of this run used Trivy 0\.52\.2/);
  assert.match(e.IaC.name, /trivy-config-v1/);
  assert.equal(R.engines({ sast: { id: 1, scan_engine: 'sonar' } }).SAST.name, 'SonarQube (legacy)');
  assert.equal(R.trivyVersion('no tools'), null);
});

test('gate rules describe the configured thresholds and fail closed on invalid config', () => {
  const def = R.gateRules({});
  const by = Object.fromEntries(def.rules.map(r => [r.stage, r]));
  assert.equal(by.Dependency.blocks, 'blocks CRITICAL always; HIGH when a fix is available');
  assert.match(by.IaC.blocks, /committed secrets/);
  assert.match(by.DAST.blocks, /not blocking/);
  const strict = Object.fromEntries(R.gateRules({ DEPENDENCY_GATE_SEVERITIES: 'CRITICAL', IAC_SECRET_SCAN: 'off' }).rules.map(r => [r.stage, r]));
  assert.doesNotMatch(strict.Dependency.blocks, /HIGH/);
  assert.match(strict.IaC.blocks, /disabled/);
  const bad = Object.fromEntries(R.gateRules({ IMAGE_GATE_SEVERITIES: 'SEVERE' }).rules.map(r => [r.stage, r]));
  assert.equal(bad['Container image'].valid, false); assert.match(bad['Container image'].blocks, /fails closed/);
});

test('dependency split: NONE rows without a CVE are clean inventory; real advisories stay findings', () => {
  const r = R.splitDependency([
    { pkg_name: 'Flask-WTF', pkg_version: '1.2.2', cve_id: null, severity: 'NONE' },
    { pkg_name: 'waitress', pkg_version: '3.0.2', cve_id: null, severity: 'NONE' },
    { pkg_name: 'flask', pkg_version: '3.0.0', cve_id: 'CVE-2026-1', severity: 'LOW', description: 'adv' },
    { pkg_name: 'x', pkg_version: '1', cve_id: 'GHSA-1', severity: 'UNKNOWN' },
  ]);
  assert.deepEqual(r.findings.map(f => f.cve_id), ['CVE-2026-1', 'GHSA-1']);
  assert.deepEqual(r.clean, [{ pkg_name: 'Flask-WTF', pkg_version: '1.2.2' }, { pkg_name: 'waitress', pkg_version: '3.0.2' }]);
});

test('SAST note: a clean completed scan reads "No findings"', () => {
  assert.equal(R.sastNote({ status: 'COMPLETED', total_issues: 0 }, []), 'No findings');
  assert.match(R.sastNote({ status: 'COMPLETED', total_issues: 3 }, []), /No execution-linked SAST details/);
  assert.equal(R.sastNote({ status: 'COMPLETED', total_issues: 1 }, [{}]), null);
  assert.equal(R.sastNote(null, []), null);
});

test('report ID is stable for the same evidence and changes when evidence changes', () => {
  const a = R.reportId(123, { b: 1, a: [1, 2] }), b = R.reportId(123, { a: [1, 2], b: 1 });
  assert.match(a, /^CSR-123-[a-f0-9]{12}$/); assert.equal(a, b);
  assert.notEqual(a, R.reportId(123, { a: [1, 2], b: 2 }));
});

test('admission evidence comes from the execution deployment record', () => {
  assert.deepEqual(R.admission({ policy_validation: { passed: true, engine: 'kubectl apply --dry-run=server', namespace: 'cloudsentinel-p-29', checkedAt: 't', violations: [] } }), { status: 'passed', engine: 'kubectl apply --dry-run=server', namespace: 'cloudsentinel-p-29', checkedAt: 't', violations: 0 });
  assert.deepEqual(R.admission({ status: 'SUCCESS' }), { status: 'not_recorded' });
  assert.equal(R.admission(null), null);
});

// ---- route: execution-123-shaped data -------------------------------------------------------------------------
const dbPath = require.resolve('../db'), authPath = require.resolve('../middleware/auth'), routePath = require.resolve('../routes/reports');
const mock = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports, children: [], paths: [] }; };
test.afterEach(() => { for (const p of [dbPath, authPath, routePath]) delete require.cache[p]; });

test('route: report carries source, timeline, engines, rules, inventory and ID; no provenance blobs or credentials', async () => {
  mock(dbPath, { query: async sql => {
    if (sql.includes('active_dast_executions')) return { rows: [] };
    if (sql.includes('JOIN projects')) return { rows: [{ ...e123, project_id: 29, name: 'test1', triggered_by: 'webhook', repo_url: 'https://u:secret@github.com/o/python-clean.git', source_branch: 'main', source_commit: sha, source_commit_message: 'ci: retrigger' }] };
    if (sql.includes('FROM sbom_components')) return { rows: [{ pkg_name: 'Flask-WTF', pkg_version: '1.2.2', cve_id: null, severity: 'NONE' }, { pkg_name: 'waitress', pkg_version: '3.0.2', cve_id: null, severity: 'NONE' }, { pkg_name: 'flask', pkg_version: '3.1.0', cve_id: 'CVE-2026-9', severity: 'LOW', description: 'advisory text' }] };
    if (sql.includes('FROM scan_results') || sql.includes('FROM iac_findings') || sql.includes('FROM image_vulnerabilities') || sql.includes('FROM dast_findings')) return { rows: [] };
    if (sql.includes('scan_history')) return { rows: [scans123.sast] };
    if (sql.includes('dependency_scans')) return { rows: [{ ...scans123.dependency, sbom_head: '"name": "trivy", "version": "0.52.2"' }] };
    if (sql.includes('iac_scans')) return { rows: [scans123.iac] };
    if (sql.includes('image_scans')) return { rows: [scans123.image] };
    if (sql.includes('dast_scans')) return { rows: [scans123.dast] };
    if (sql.includes('deployment_history')) return { rows: [{ ...deploy123, staging_url: 'http://192.168.49.2:32559', policy_validation: { passed: true, violations: [] } }] };
    return { rows: [] };
  } });
  mock(authPath, (req, res, next) => next());
  const h = require(routePath).stack[0].route.stack[1].handle, out = {};
  await h({ params: { projectId: '29', executionId: '123' }, user: { id: 3 } }, { status(c) { out.status = c; return this; }, json(x) { out.body = x; return this; } });
  const b = out.body;
  assert.equal(out.status, undefined);
  assert.match(b.report.id, /^CSR-123-[a-f0-9]{12}$/); assert.ok(Date.parse(b.report.generatedAt));
  assert.deepEqual([b.source.repository, b.source.branch, b.source.commit, b.source.message], ['https://github.com/o/python-clean', 'main', sha, 'ci: retrigger']);
  assert.equal(b.timing.durationMs, 35328);
  assert.equal(b.stages.length, 6);
  assert.equal(b.engines.SAST.version, '3.0.0'); assert.equal(b.engines.Dependency.version, '0.52.2');
  assert.ok(b.gateRules.rules.length >= 6);
  assert.deepEqual(b.findings.dependency.map(f => f.pkg_name), ['flask']);
  assert.deepEqual(b.inventory.dependencyClean.map(f => f.pkg_name), ['Flask-WTF', 'waitress']);
  assert.equal(b.counts.total, 1); assert.equal(b.counts.bySeverity.UNKNOWN, 0);
  assert.equal(b.limitations.sastDetails, 'No findings');
  assert.equal(b.kubernetes.admission.status, 'passed');
  const text = JSON.stringify(b);
  assert.doesNotMatch(text, /secret@|tool_provenance|sbom_head|policy_validation|source_commit_message/);
});
