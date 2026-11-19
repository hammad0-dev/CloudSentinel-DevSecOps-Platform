"use strict";
// ML engine plumbing (SAST_ENGINE / DAST_ENGINE): clients, persistence, gate counting, flag defaults,
// and fail-fast behaviour when the ML service is unreachable. ML services are mocked with local HTTP
// servers; no PostgreSQL, SonarQube, ZAP or Python is needed (python3 runs the SQLite gate model).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const vm = require("vm");
const { spawnSync } = require("child_process");
const { createRequire } = require("module");

const { createMlSastClient } = require("../services/ml/mlSastClient");
const { createMlDastClient } = require("../services/ml/mlDastClient");
const engines = require("../services/ml/engines");
const { runMlSast, collectSourceFiles, toIssues } = require("../services/ml/mlSastScan");
const { runMlBaselineScan } = require("../services/ml/mlDastScan");
const { coerceIssueRow } = require("../routes/sast/config");
const { fingerprint } = require("../services/dastBaselineScanner");
const { normalize } = require("../services/governance/normalize");
const stageProvenance = require("../services/stageProvenance");

const SHA = "a".repeat(64);
const TRAINED = (name) => ({ name, version: "1.0.0", sha256: SHA, trained_on: "fixture-set-v1", metrics: { f1: 0.81 }, status: "trained" });
const UNTRAINED = (name) => ({ name, version: "untrained", sha256: null, trained_on: null, metrics: {}, status: "untrained" });

// ---- helpers ----
function withEnv(vars, fn) {
  const old = {};
  for (const [k, v] of Object.entries(vars)) { old[k] = process.env[k]; if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  const restore = () => { for (const [k, v] of Object.entries(old)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } };
  return Promise.resolve().then(fn).finally(restore);
}

async function mockService({ info, findings = [], scanStatus = 200, hang = false }) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : null });
      if (hang) return; // never answers
      const send = (status, data) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(data)); };
      if (req.url === "/model-info") return send(200, info);
      if (req.url === "/health") return send(200, { status: "ok" });
      if (req.url === "/scan") return scanStatus === 200 ? send(200, { findings }) : send(scanStatus, { detail: "model scan failed: RuntimeError" });
      return send(404, { detail: "not found" });
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  return { url, requests, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

async function closedPortUrl() {
  const server = http.createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  await new Promise((r) => server.close(r));
  return `http://127.0.0.1:${port}`;
}

function sourceTree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cs-ml-sast-"));
  const write = (rel, text) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), text); };
  write("app.py", "import sqlite3\ncur.execute('SELECT * FROM users WHERE id=' + uid)\n");
  write("src/server.js", "app.get('/q', (req, res) => res.send(req.query.q));\n");
  write("node_modules/lodash/index.js", "module.exports = {};\n");
  write("README.md", "# fixture\n");
  return dir;
}

// In-memory scan_history/scan_results that behaves like the PostgreSQL statements sastEvidence runs.
function sastDb({ projectId = 11, scanId = 49, executionId = 23 } = {}) {
  const scan = { id: scanId, project_id: projectId, pipeline_execution_id: executionId, status: "RUNNING", sast_details_linked: false, critical: 0, high: 0, medium: 0, low: 0, total_issues: 0 };
  const results = [];
  const calls = [];
  const up = (s) => String(s || "").toUpperCase();
  const query = async (sql, params = []) => {
    calls.push({ sql, params });
    if (sql.startsWith("UPDATE scan_history SET scan_engine")) {
      if (params[1] !== scan.id || params[2] !== scan.project_id || scan.status !== "RUNNING") return { rows: [] };
      scan.scan_engine = "ml"; scan.tool_provenance = JSON.parse(params[0]); return { rows: [{ id: scan.id }] };
    }
    if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rows: [] };
    if (sql.startsWith("DELETE FROM scan_results")) { results.length = 0; return { rows: [] }; }
    if (sql.startsWith("INSERT INTO scan_results")) {
      const [project_id, scan_history_id, rule, severity, message, file_path, line_number, issue_type, hotspot_review] = params;
      results.push({ id: results.length + 1, project_id, scan_history_id, rule, severity, message, file_path, line_number, issue_type, hotspot_review });
      return { rows: [] };
    }
    if (sql.startsWith("SELECT COUNT(*)::int")) {
      const rows = results.filter((r) => r.project_id === params[0] && r.scan_history_id === params[1]);
      const n = (f) => rows.filter(f).length;
      return { rows: [{ total: rows.length, distinct_total: new Set(rows.map((r) => JSON.stringify([r.rule, r.severity, r.message, r.file_path, r.line_number]))).size,
        critical: n((r) => ["CRITICAL", "BLOCKER"].includes(up(r.severity))), high: n((r) => ["MAJOR", "HIGH"].includes(up(r.severity))),
        medium: n((r) => ["MINOR", "MEDIUM", "LOW"].includes(up(r.severity))), low: n((r) => !["CRITICAL", "BLOCKER", "MAJOR", "HIGH", "MINOR", "MEDIUM", "LOW"].includes(up(r.severity))) }] };
    }
    if (sql.trim().startsWith("UPDATE scan_history SET status = 'COMPLETED'")) {
      Object.assign(scan, { status: "COMPLETED", sast_details_linked: true, total_issues: params[0], critical: params[1], high: params[2], medium: params[3], low: params[4] });
      return { rows: [{ id: scan.id }] };
    }
    if (sql.startsWith("UPDATE scan_history SET status = 'FAILED'")) { scan.status = "FAILED"; return { rows: [] }; }
    throw new Error(`unexpected SQL in sastDb: ${sql.slice(0, 80)}`);
  };
  const client = { query, release() {} };
  return { pool: { query, connect: async () => client }, scan, results, calls };
}

// Runs the orchestrator's real SAST gate SQL over the persisted rows (SQLite model, as in
// sast-gate-counting.test.js).
function gateOver(scan, results) {
  const file = require.resolve("../services/orchestrator"), local = createRequire(file);
  const pool = { async query(sql, params) {
    if (!sql.includes("FROM scan_history sh")) return { rows: [] };
    const translated = sql.replaceAll("::int", "").replace(/COUNT\(DISTINCT \((sr\.rule, sr\.severity, sr\.message, sr\.file_path, sr\.line_number)\)\)/, "COUNT(DISTINCT json_array($1))").replaceAll("$1", "?1").replaceAll("$2", "?2");
    const out = spawnSync("python3", ["-c", `
import json,sqlite3,sys
x=json.load(sys.stdin); db=sqlite3.connect(':memory:'); db.row_factory=sqlite3.Row
db.execute('CREATE TABLE scan_history (id INTEGER PRIMARY KEY, project_id INTEGER, pipeline_execution_id INTEGER, status TEXT, sast_details_linked BOOLEAN, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, total_issues INTEGER)')
db.execute('CREATE TABLE scan_results (id INTEGER PRIMARY KEY, project_id INTEGER, scan_history_id INTEGER, rule TEXT, severity TEXT, message TEXT, file_path TEXT, line_number INTEGER, issue_type TEXT, hotspot_review TEXT)')
for table in ['scan_history','scan_results']:
 for r in x[table]: db.execute('INSERT INTO '+table+' ('+','.join(r)+') VALUES ('+','.join('?' for _ in r)+')',list(r.values()))
print(json.dumps([dict(r) for r in db.execute(x['sql'],x['params'])]))
`], { input: JSON.stringify({ sql: translated, params, scan_history: [scan], scan_results: results }), encoding: "utf8", timeout: 5000 });
    assert.equal(out.status, 0, out.stderr);
    return { rows: JSON.parse(out.stdout) };
  } };
  const { id, project_id, pipeline_execution_id, status, sast_details_linked, critical, high, medium, low, total_issues } = scan;
  scan = { id, project_id, pipeline_execution_id, status, sast_details_linked, critical, high, medium, low, total_issues };
  const stubs = { "../db": pool, "./deployment": {}, axios: {}, jsonwebtoken: {} };
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(file, "utf8"), { module, exports: module.exports, require: (id) => (Object.hasOwn(stubs, id) ? stubs[id] : local(id)), process: { env: {} }, console: { log() {}, warn() {}, error() {} }, setTimeout });
  return module.exports.checkCriticalFindings(scan.project_id, scan.pipeline_execution_id, "SAST");
}

// In-memory dast_scans/dast_findings for the baseline persistence statements.
function dastDb({ projectId = 11, executionId = 23, stagingUrl = "http://192.168.49.2:31281" } = {}) {
  const scans = [];
  const findings = [];
  const query = async (sql, params = []) => {
    if (sql.startsWith("SELECT id, staging_url FROM deployment_history")) return { rows: [{ id: 5, staging_url: stagingUrl }] };
    if (sql.startsWith("SELECT id FROM dast_scans WHERE project_id=$1 AND status='RUNNING'")) return { rows: scans.filter((s) => s.status === "RUNNING") };
    if (sql.startsWith("INSERT INTO dast_scans")) { const s = { id: 70 + scans.length, project_id: params[0], pipeline_execution_id: params[1], target_url: params[2], status: "RUNNING", scan_mode: "BASELINE", policy_name: "ml-dast", policy_version: "pending", target_authorization: JSON.parse(params[4]), scan_engine: "ml" }; scans.push(s); return { rows: [{ id: s.id }] }; }
    if (sql.startsWith("UPDATE dast_scans SET policy_name")) { Object.assign(scans.find((s) => s.id === params[3]), { policy_name: params[0], policy_version: params[1], tool_provenance: JSON.parse(params[2]) }); return { rows: [], rowCount: 1 }; }
    if (sql.startsWith("UPDATE dast_scans SET status='FAILED'")) { const s = scans.find((x) => x.id === params[1]); if (s?.status === "RUNNING") Object.assign(s, { status: "FAILED", failure_reason: params[0] }); return { rows: [], rowCount: 1 }; }
    if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rows: [] };
    if (sql.startsWith("DELETE FROM dast_findings")) return { rows: [], rowCount: 0 };
    if (sql.startsWith("INSERT INTO dast_findings")) {
      const keys = ["scan_id", "project_id", "alert", "attack_type", "severity", "endpoint", "method", "param", "request_payload", "response_details", "cwe_id", "solution", "finding_fingerprint"];
      findings.push({ id: findings.length + 1, ...Object.fromEntries(keys.map((k, i) => [k, params[i]])) });
      return { rows: [{ id: findings.length }], rowCount: 1 };
    }
    if (sql.startsWith("SELECT COUNT(*)::int AS total")) {
      const rows = findings.filter((f) => f.project_id === params[0] && f.scan_id === params[1]);
      const n = (s) => rows.filter((f) => f.severity === s).length;
      return { rows: [{ total: rows.length, high: n("HIGH"), medium: n("MEDIUM"), low: n("LOW"), informational: n("INFORMATIONAL"), fingerprints: new Set(rows.map((f) => f.finding_fingerprint)).size }] };
    }
    if (sql.startsWith("UPDATE dast_scans SET status='COMPLETED'")) { const s = scans.find((x) => x.id === params[5]); Object.assign(s, { status: "COMPLETED", total_findings: params[0], high: params[1], medium: params[2], low: params[3], informational: params[4] }); return { rows: [{ id: s.id }], rowCount: 1 }; }
    throw new Error(`unexpected SQL in dastDb: ${sql.slice(0, 80)}`);
  };
  return { pool: { query, connect: async () => ({ query, release() {} }) }, scans, findings, projectId, executionId, stagingUrl };
}

const SAST_FINDINGS = [
  { rule: "python.sql-injection", cwe_id: 89, severity: "CRITICAL", message: "SQL query built from user input", file_path: "app.py", line_number: 2, confidence: 0.93 },
  { rule: "js.reflected-xss", cwe_id: 79, severity: "HIGH", message: "User input reflected in response", file_path: "src/server.js", line_number: 1, confidence: 0.71 },
  { rule: "js.reflected-xss", cwe_id: 79, severity: "HIGH", message: "User input reflected in response", file_path: "src/server.js", line_number: 1, confidence: 0.70 },
];
const DAST_FINDINGS = (base) => [
  { alert: "Reflected XSS", attack_type: "xss", severity: "HIGH", endpoint: `${base}/search`, method: "get", param: "q", request_payload: "<script>alert(1)</script>", response_details: "payload reflected", cwe_id: 79, solution: "Encode output", confidence: 0.88 },
  { alert: "Missing CSP header", attack_type: "headers", severity: "LOW", endpoint: `${base}/`, method: "GET", param: "", request_payload: "", response_details: "", cwe_id: 693, solution: "Set Content-Security-Policy", confidence: 0.99 },
];

// ---- flags ----
test("engine flags default to sonar and zap, accept ml, reject anything else", () =>
  withEnv({ SAST_ENGINE: undefined, DAST_ENGINE: undefined }, async () => {
    assert.equal(engines.sastEngine(), "sonar");
    assert.equal(engines.dastEngine(), "zap");
    process.env.SAST_ENGINE = " ML "; process.env.DAST_ENGINE = "ml";
    assert.equal(engines.sastEngine(), "ml");
    assert.equal(engines.dastEngine(), "ml");
    process.env.SAST_ENGINE = "semgrep";
    assert.throws(() => engines.sastEngine(), /SAST_ENGINE=semgrep is not supported; use sonar or ml/);
  }));

test("untrained models are refused unless ML_ALLOW_UNTRAINED=true", () =>
  withEnv({ ML_ALLOW_UNTRAINED: undefined }, async () => {
    const info = { name: "ml-sast", version: "untrained", sha256: null, status: "untrained" };
    assert.throws(() => engines.requireUsableModel(info, "ML SAST"), (e) => e.code === "ML_MODEL_UNTRAINED" && /refusing to report a clean scan/.test(e.message));
    process.env.ML_ALLOW_UNTRAINED = "true";
    assert.equal(engines.requireUsableModel(info, "ML SAST"), info);
    assert.equal(engines.toolProvenance({ ...info, sha256: SHA, version: "2.1.0" }).tool, `ml-sast 2.1.0 sha256:${SHA}`);
  }));

// ---- clients ----
test("clients read ML_SAST_URL / ML_DAST_URL and report a missing URL clearly", () =>
  withEnv({ ML_SAST_URL: undefined, ML_DAST_URL: "http://ml-dast:8002/" }, async () => {
    assert.throws(() => createMlSastClient(), /ML_SAST_URL is not set/);
    assert.equal(createMlDastClient().url, "http://ml-dast:8002");
    assert.throws(() => createMlSastClient({ url: "ftp://x" }), /ML_SAST_URL must be an http\(s\) URL/);
  }));

test("unreachable ML service fails fast with the URL and cause", async () => {
  const url = await closedPortUrl();
  const started = Date.now();
  await assert.rejects(createMlSastClient({ url, timeoutMs: 5000 }).modelInfo(), (e) => e.code === "ML_SERVICE_UNREACHABLE" && e.message.includes(`ML SAST service at ${url} is unreachable (ECONNREFUSED)`));
  await assert.rejects(createMlDastClient({ url, timeoutMs: 5000 }).scan({ baseUrl: "http://x", maxPages: 1, maxRequests: 1 }), /ML DAST service at .* is unreachable/);
  assert.ok(Date.now() - started < 3000);
});

test("a hanging ML service times out instead of hanging the stage", async () => {
  const svc = await mockService({ info: TRAINED("ml-sast"), hang: true });
  const started = Date.now();
  try {
    await assert.rejects(createMlSastClient({ url: svc.url, timeoutMs: 300 }).modelInfo(), (e) => e.code === "ML_SERVICE_TIMEOUT" && /did not respond within 0s|did not respond within/.test(e.message));
    assert.ok(Date.now() - started < 3000, "timeout must bound the call");
  } finally { await svc.close(); }
});

test("HTTP errors and malformed findings are rejected with clear messages", async () => {
  const failing = await mockService({ info: TRAINED("ml-sast"), scanStatus: 500 });
  const bogus = await mockService({ info: TRAINED("ml-sast"), findings: [{ ...SAST_FINDINGS[0], severity: "SEVERE" }] });
  const foreign = await mockService({ info: TRAINED("ml-sast"), findings: [{ ...SAST_FINDINGS[0], file_path: "/etc/passwd" }] });
  const noSha = await mockService({ info: { ...TRAINED("ml-sast"), sha256: "" } });
  const files = [{ path: "app.py", content: "x" }];
  try {
    await assert.rejects(createMlSastClient({ url: failing.url }).scan(files), /returned HTTP 500: model scan failed: RuntimeError/);
    await assert.rejects(createMlSastClient({ url: bogus.url }).scan(files), /findings\[0\]\.severity "SEVERE" is not CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO/);
    await assert.rejects(createMlSastClient({ url: foreign.url }).scan(files), /file_path "\/etc\/passwd" was not submitted/);
    await assert.rejects(createMlSastClient({ url: noSha.url }).modelInfo(), /a trained model must report its SHA-256/);
  } finally { await Promise.all([failing, bogus, foreign, noSha].map((s) => s.close())); }
});

// ---- SAST persistence + gate ----
test("source collection sends only Python/Node sources and skips vendored dirs", () => {
  const dir = sourceTree();
  try {
    const { files } = collectSourceFiles(dir);
    assert.deepEqual(files.map((f) => f.path), ["app.py", "src/server.js"]);
    assert.throws(() => collectSourceFiles(dir, { maxFiles: 1, maxFileBytes: 1e6, maxTotalBytes: 1e9 }), /exceeds the ML SAST input limit/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("ML SAST persists findings into scan_results with the Sonar row shape, provenance, and the gate counts them", async () => {
  const svc = await mockService({ info: TRAINED("ml-sast-codebert"), findings: SAST_FINDINGS });
  const dir = sourceTree();
  const db = sastDb();
  try {
    const out = await runMlSast({ pool: db.pool, projectId: 11, scanHistoryId: 49, cloneTarget: dir, provenance: null, coerceIssueRow, client: createMlSastClient({ url: svc.url }) });
    const scanReq = svc.requests.find((r) => r.url === "/scan");
    assert.deepEqual(scanReq.body.files.map((f) => f.path), ["app.py", "src/server.js"]);
    assert.deepEqual(out.summary, { critical: 1, high: 1, medium: 0, low: 0, total: 2 }, "duplicate model output collapses to one row");
    assert.equal(db.scan.status, "COMPLETED");
    assert.equal(db.scan.sast_details_linked, true);
    assert.deepEqual(db.results.map(({ rule, severity, file_path, line_number, issue_type, hotspot_review }) => ({ rule, severity, file_path, line_number, issue_type, hotspot_review })), [
      { rule: "ml:python.sql-injection:CWE-89", severity: "CRITICAL", file_path: "app.py", line_number: 2, issue_type: "VULNERABILITY", hotspot_review: "NOT_APPLICABLE" },
      { rule: "ml:js.reflected-xss:CWE-79", severity: "HIGH", file_path: "src/server.js", line_number: 1, issue_type: "VULNERABILITY", hotspot_review: "NOT_APPLICABLE" },
    ]);
    assert.equal(db.scan.scan_engine, "ml");
    assert.equal(db.scan.tool_provenance.tool, `ml-sast-codebert 1.0.0 sha256:${SHA}`);
    assert.equal(db.scan.tool_provenance.model.sha256, SHA);
    assert.equal(db.scan.tool_provenance.files, 2);
    assert.match(db.scan.tool_provenance.inputSha256, /^[a-f0-9]{64}$/);

    const gate = await gateOver(db.scan, db.results);
    assert.equal(gate.evidenceFound, true);
    assert.equal(gate.evidenceConsistent, true);
    assert.equal(gate.hasCritical, true);
    assert.equal(gate.hasHigh, true);

    const normalized = normalize("SAST", db.results[0], { project_id: 11, scan_id: 49, detailTable: "scan_results", mode: "SAST" });
    assert.equal(normalized.severity, "CRITICAL");
    assert.equal(normalized.location, "app.py:2");
    assert.deepEqual(normalized.references, ["CWE-89"]);
    assert.match(normalized.fingerprint, /^[a-f0-9]{64}$/);
  } finally { await svc.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("ML SAST with zero findings passes the gate with consistent evidence", async () => {
  const svc = await mockService({ info: TRAINED("ml-sast"), findings: [] });
  const dir = sourceTree();
  const db = sastDb();
  try {
    await runMlSast({ pool: db.pool, projectId: 11, scanHistoryId: 49, cloneTarget: dir, coerceIssueRow, client: createMlSastClient({ url: svc.url }) });
    const gate = await gateOver(db.scan, db.results);
    assert.deepEqual([gate.evidenceConsistent, gate.hasCritical, gate.hasHigh, gate.requiresReview], [true, false, false, false]);
  } finally { await svc.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("ML SAST refuses untrained models, provenance-bound runs, and repos without Python/Node sources", () =>
  withEnv({ ML_ALLOW_UNTRAINED: undefined }, async () => {
    const svc = await mockService({ info: UNTRAINED("ml-sast") });
    const dir = sourceTree();
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), "cs-ml-empty-"));
    try {
      const client = createMlSastClient({ url: svc.url });
      await assert.rejects(runMlSast({ pool: sastDb().pool, projectId: 11, scanHistoryId: 49, cloneTarget: dir, coerceIssueRow, client }), /model is untrained/);
      assert.equal(svc.requests.some((r) => r.url === "/scan"), false, "nothing is scanned with an untrained model");
      await assert.rejects(runMlSast({ pool: sastDb().pool, projectId: 11, scanHistoryId: 49, cloneTarget: dir, provenance: { artifact: { sha256: SHA } }, coerceIssueRow, client }), (e) => e.code === "ML_ENGINE_PROVENANCE_UNSUPPORTED");
      process.env.ML_ALLOW_UNTRAINED = "true";
      await assert.rejects(runMlSast({ pool: sastDb().pool, projectId: 11, scanHistoryId: 49, cloneTarget: empty, coerceIssueRow, client }), /No Python or Node\.js source files found/);
      const db = sastDb();
      await runMlSast({ pool: db.pool, projectId: 11, scanHistoryId: 49, cloneTarget: dir, coerceIssueRow, client });
      assert.equal(db.scan.tool_provenance.tool, "ml-sast untrained sha256:untrained");
    } finally { await svc.close(); fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(empty, { recursive: true, force: true }); }
  }));

test("toIssues keeps an existing CWE in the rule and maps findings to VULNERABILITY issues", () => {
  const [issue] = toIssues([{ rule: "CWE-78 shell injection", cwe_id: 78, severity: "HIGH", message: "m", file_path: "a.py", line_number: null, confidence: 0.5 }]);
  assert.deepEqual([issue.rule, issue.type, issue.component, issue.line], ["ml:CWE-78 shell injection", "VULNERABILITY", "a.py", null]);
  assert.deepEqual(coerceIssueRow(issue, 3), [3, "ml:CWE-78 shell injection", "HIGH", "m", "a.py", null]);
});

// ---- DAST persistence ----
test("ML DAST persists findings into dast_findings with ZAP-compatible fingerprints and model provenance", async () => {
  const db = dastDb();
  const svc = await mockService({ info: TRAINED("ml-dast-gbm"), findings: [...DAST_FINDINGS(db.stagingUrl), DAST_FINDINGS(db.stagingUrl)[0]] });
  const binding = stageProvenance.binding;
  stageProvenance.binding = async () => null;
  try {
    const out = await runMlBaselineScan({ pool: db.pool, projectId: 11, executionId: 23, targetUrl: db.stagingUrl, userId: 3, client: createMlDastClient({ url: svc.url }), maxPages: 7, maxRequests: 70 });
    assert.deepEqual(svc.requests.find((r) => r.url === "/scan").body, { baseUrl: db.stagingUrl, maxPages: 7, maxRequests: 70 });
    assert.deepEqual(out.summary, { total: 2, high: 1, medium: 0, low: 1, informational: 0 });
    const [scan] = db.scans;
    assert.deepEqual([scan.status, scan.scan_mode, scan.pipeline_execution_id, scan.total_findings, scan.high, scan.low], ["COMPLETED", "BASELINE", 23, 2, 1, 1]);
    assert.deepEqual([scan.policy_name, scan.policy_version, scan.scan_engine], ["ml-dast-gbm", "1.0.0", "ml"]);
    assert.equal(scan.tool_provenance.tool, `ml-dast-gbm 1.0.0 sha256:${SHA}`);
    assert.equal(scan.target_authorization.type, "verified_staging_deployment");
    assert.equal(db.findings.length, 2);
    const xss = db.findings[0];
    assert.equal(xss.method, "GET");
    assert.equal(xss.cwe_id, 79);
    const { finding_fingerprint, id, scan_id, project_id, ...fields } = xss;
    assert.equal(finding_fingerprint, fingerprint(fields), "same fingerprint function as the ZAP baseline");
    const normalized = normalize("DAST", xss, { project_id: 11, scan_id: scan.id, detailTable: "dast_findings", mode: "BASELINE" });
    assert.deepEqual([normalized.source, normalized.severity, normalized.references[0]], ["DAST", "HIGH", "CWE-79"]);
  } finally { stageProvenance.binding = binding; await svc.close(); }
});

test("ML DAST only scans the verified staging target and records failures on the scan row", async () => {
  const db = dastDb();
  const binding = stageProvenance.binding;
  stageProvenance.binding = async () => null;
  const url = await closedPortUrl();
  try {
    await assert.rejects(runMlBaselineScan({ pool: db.pool, projectId: 11, executionId: 23, targetUrl: "http://evil.example", userId: 3, client: createMlDastClient({ url }) }), /not the verified staging deployment/);
    assert.equal(db.scans.length, 0);
    await assert.rejects(runMlBaselineScan({ pool: db.pool, projectId: 11, executionId: 23, targetUrl: db.stagingUrl, userId: 3, client: createMlDastClient({ url }) }), /ML DAST service at .* is unreachable/);
    assert.equal(db.scans[0].status, "FAILED");
    assert.match(db.scans[0].failure_reason, /unreachable \(ECONNREFUSED\)/);
    stageProvenance.binding = async () => ({ commit_sha: "c".repeat(40) });
    await assert.rejects(runMlBaselineScan({ pool: db.pool, projectId: 11, executionId: 23, targetUrl: db.stagingUrl, userId: 3, client: createMlDastClient({ url }) }), (e) => e.code === "ML_ENGINE_PROVENANCE_UNSUPPORTED");
  } finally { stageProvenance.binding = binding; }
});

// ---- routes: the flag default keeps the old engine ----
const dbPath = require.resolve("../db");
let routePool = { query: async () => ({ rows: [] }) };
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: { query: (...a) => routePool.query(...a), connect: (...a) => routePool.connect(...a) } };

function handlerOf(router, routePath) {
  const layer = router.stack.find((l) => l.route?.path === routePath && l.route.methods.post);
  return layer.route.stack.at(-1).handle;
}
async function invoke(handler, projectId) {
  const res = { statusCode: 200, headersSent: false, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; this.headersSent = true; return this; }, set() { return this; } };
  await handler({ params: { projectId: String(projectId) }, user: { id: 3 }, body: {} }, res);
  return res;
}

const zapCalls = [];
const dastScanner = require("../services/dastBaselineScanner");
dastScanner.runBaselineScan = async (args) => { zapCalls.push(args); return { scanId: 1, summary: { total: 0 }, total: 0, scanMode: "BASELINE" }; };
const dastHandler = handlerOf(require("../routes/dast"), "/scan/:projectId");

test("DAST route: default flag runs the ZAP baseline path; DAST_ENGINE=ml uses ml-dast and fails clearly when unreachable", async () => {
  const db = dastDb({ stagingUrl: "http://owner.example" });
  routePool = { query: async (sql, p) => (sql.startsWith("SELECT id,target_url FROM projects") ? { rows: [{ id: 11, target_url: "http://owner.example" }] } : db.pool.query(sql, p)), connect: db.pool.connect };
  const binding = stageProvenance.binding;
  stageProvenance.binding = async () => null;
  try {
    await withEnv({ DAST_ENGINE: undefined }, async () => {
      const res = await invoke(dastHandler, 11);
      assert.equal(res.statusCode, 200, JSON.stringify(res.body));
      assert.equal(zapCalls.length, 1, "ZAP baseline scanner is the default");
      assert.equal(db.scans.length, 0);
    });
    const url = await closedPortUrl();
    await withEnv({ DAST_ENGINE: "ml", ML_DAST_URL: url }, async () => {
      const started = Date.now();
      const res = await invoke(dastHandler, 11);
      assert.equal(res.statusCode, 502);
      assert.match(res.body.error, /ML DAST service at http:\/\/127\.0\.0\.1:\d+ is unreachable \(ECONNREFUSED\)/);
      assert.equal(zapCalls.length, 1, "ZAP is not called when DAST_ENGINE=ml");
      assert.equal(db.scans[0].status, "FAILED");
      assert.ok(Date.now() - started < 3000);
    });
  } finally { stageProvenance.binding = binding; }
});

const sonarCalls = [];
const sastConfig = require("../routes/sast/config");
sastConfig.assertSonarReachable = async () => { sonarCalls.push(1); throw new Error("SONAR_PATH_TAKEN"); };
const sastPipeline = require("../routes/sast/pipeline");
sastPipeline.gitCloneAsync = async (_url, target) => { const src = sourceTree(); fs.cpSync(src, target, { recursive: true }); fs.rmSync(src, { recursive: true, force: true }); };
require("../services/staticStageFailure").save = () => "(test: not persisted)";
const sastHandler = handlerOf(require("../routes/sast"), "/scan/:projectId");

function sastRoutePool(db) {
  return { query: async (sql, p) => {
    if (sql.startsWith("SELECT * FROM projects")) return { rows: [{ id: 11, user_id: 3, repo_url: "https://github.com/example/app", is_private: false }] };
    if (sql.startsWith("SELECT id FROM scan_history WHERE project_id") || sql.startsWith("SELECT id FROM dependency_scans")) return { rows: [] };
    if (sql.startsWith("INSERT INTO scan_history")) { db.scan.status = "RUNNING"; return { rows: [{ id: db.scan.id }] }; }
    if (sql.trim().startsWith("UPDATE scan_history SET status = 'FAILED'")) { db.scan.status = "FAILED"; return { rows: [] }; }
    return db.pool.query(sql, p);
  }, connect: db.pool.connect };
}

test("SAST route: default flag keeps SonarQube; SAST_ENGINE=ml persists ML findings and fails clearly when unreachable", async () => {
  const cloneRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cs-ml-clone-"));
  const prepare = stageProvenance.prepare;
  stageProvenance.prepare = async () => null;
  try {
    await withEnv({ SAST_ENGINE: undefined, CLONE_DIR: cloneRoot }, async () => {
      const db = sastDb();
      routePool = sastRoutePool(db);
      const res = await invoke(sastHandler, 11);
      assert.equal(sonarCalls.length, 1, "SonarQube path is the default");
      assert.equal(res.statusCode, 500);
      assert.match(res.body.error, /SONAR_PATH_TAKEN/);
    });

    const svc = await mockService({ info: TRAINED("ml-sast"), findings: SAST_FINDINGS });
    await withEnv({ SAST_ENGINE: "ml", ML_SAST_URL: svc.url, CLONE_DIR: cloneRoot }, async () => {
      const db = sastDb();
      routePool = sastRoutePool(db);
      const res = await invoke(sastHandler, 11);
      assert.equal(res.statusCode, 200, JSON.stringify(res.body));
      assert.deepEqual([res.body.engine, res.body.summary.critical, res.body.summary.high, res.body.total], ["ml", 1, 1, 2]);
      assert.equal(res.body.tool, `ml-sast 1.0.0 sha256:${SHA}`);
      assert.equal(db.scan.status, "COMPLETED");
      assert.equal(sonarCalls.length, 1, "SonarQube is not contacted when SAST_ENGINE=ml");
    }).finally(() => svc.close());

    const url = await closedPortUrl();
    await withEnv({ SAST_ENGINE: "ml", ML_SAST_URL: url, CLONE_DIR: cloneRoot }, async () => {
      const db = sastDb();
      routePool = sastRoutePool(db);
      const started = Date.now();
      const res = await invoke(sastHandler, 11);
      assert.equal(res.statusCode, 500);
      assert.match(res.body.error, /ML SAST service at http:\/\/127\.0\.0\.1:\d+ is unreachable \(ECONNREFUSED\)/);
      assert.equal(db.scan.status, "FAILED");
      assert.ok(Date.now() - started < 3000);
    });
  } finally { stageProvenance.prepare = prepare; fs.rmSync(cloneRoot, { recursive: true, force: true }); }
});
