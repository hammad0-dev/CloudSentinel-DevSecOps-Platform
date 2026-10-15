const assert = require("node:assert/strict");
const test = require("node:test");
const { authorizeTarget, extractFindings, summarize, persistCompletedScan, runBaselineScan } = require("../services/dastBaselineScanner");

test("pipeline DAST accepts only its exact successful staging deployment", async () => {
  const pool = { query: async (sql, args) => { assert.match(sql, /deployment_history/); assert.deepEqual(args, [17, 44]); return { rows: [{ id: 9, staging_url: "http://staging.example:30123" }] }; } };
  const ok = await authorizeTarget(pool, { projectId: 17, executionId: 44, targetUrl: "http://staging.example:30123/", userId: 3 });
  assert.equal(ok.authorization.type, "verified_staging_deployment");
  await assert.rejects(() => authorizeTarget(pool, { projectId: 17, executionId: 44, targetUrl: "http://other.example", userId: 3 }), /not the verified staging deployment/);
  await assert.rejects(() => authorizeTarget({ query: async () => ({ rows: [] }) }, { projectId: 17, executionId: 45, targetUrl: "http://staging.example", userId: 3 }), /not the verified staging deployment/);
});

test("manual DAST requires a legitimate owner identity and HTTP(S) target", async () => {
  const ok = await authorizeTarget({}, { projectId: 17, targetUrl: "https://owner-approved.example", userId: 3 });
  assert.equal(ok.authorization.type, "owner_configured_target");
  await assert.rejects(() => authorizeTarget({}, { projectId: 17, targetUrl: "file:///etc/passwd", userId: 3 }), /HTTP or HTTPS/);
  await assert.rejects(() => authorizeTarget({}, { projectId: 17, targetUrl: "https://owner-approved.example", userId: null }), /Owner authorization/);
});

test("ZAP parsing fingerprints findings and supports legitimate zero findings", () => {
  const findings = extractFindings({ site: [{ alerts: [{ name: "XSS", pluginid: "40012", riskcode: "3", instances: [{ uri: "http://staging/a", method: "get" }] }] }] });
  assert.equal(findings.length, 1); assert.equal(findings[0].severity, "HIGH"); assert.match(findings[0].finding_fingerprint, /^[a-f0-9]{64}$/);
  assert.deepEqual(summarize(extractFindings({ site: [] })), { total: 0, high: 0, medium: 0, low: 0, informational: 0 });
  assert.throws(() => extractFindings(null), /invalid JSON structure/);
});

test("persistence rolls back on failed insert, count mismatch, and fingerprint conflict", async () => {
  for (const mode of ["insert", "count", "fingerprint"]) {
    const calls = []; const client = { query: async (sql) => { calls.push(sql); if (sql === "BEGIN" || sql.startsWith("DELETE")) return { rowCount: 1, rows: [] }; if (sql.startsWith("INSERT")) { if (mode === "insert") throw new Error("unique violation"); return { rowCount: 1, rows: [] }; } if (sql.startsWith("SELECT COUNT")) return { rows: [{ total: 1, high: 0, medium: 0, low: 1, informational: 0, fingerprints: mode === "fingerprint" ? 0 : 1 }] }; return { rowCount: 1, rows: [] }; }, release() { calls.push("RELEASE"); } };
    const pool = { connect: async () => client };
    await assert.rejects(() => persistCompletedScan(pool, 101, 17, [{ alert: "a", attack_type: "a", severity: "LOW", endpoint: "u", method: "GET", param: "", request_payload: "", response_details: "", cwe_id: null, solution: "", finding_fingerprint: "a".repeat(64) }], { total: 1, high: 0, medium: 0, low: mode === "count" ? 0 : 1, informational: 0 }));
    assert.ok(calls.includes("ROLLBACK")); assert.ok(!calls.includes("COMMIT"));
  }
});

test("runner/report errors mark only the new scan failed and do not touch history", async () => {
  const calls = []; const pool = { query: async (sql) => { calls.push(sql); if (sql.includes("deployment_history")) return { rows: [{ id: 9, staging_url: "http://staging.example" }] }; if (sql.startsWith("SELECT id FROM dast_scans")) return { rows: [] }; if (sql.startsWith("INSERT INTO dast_scans")) return { rows: [{ id: 101 }] }; return { rows: [], rowCount: 1 }; } };
  const fakeFs = { mkdtempSync: () => "/tmp/dast-unit", existsSync: () => false, rmSync() {} };
  await assert.rejects(() => runBaselineScan({ pool, projectId: 17, executionId: 44, targetUrl: "http://staging.example", userId: 3, runner: async () => { throw new Error("timeout"); }, fsImpl: fakeFs }), /timeout/);
  assert.ok(calls.some((sql) => sql.includes("WHERE id=$2 AND project_id=$3 AND status='RUNNING'")));
  assert.ok(!calls.some((sql) => /^DELETE FROM dast_findings WHERE project_id = \$1"/.test(sql)));
});
﻿
test("missing, unreadable, and malformed report files fail only the new scan", async () => {
  for (const mode of ["missing", "unreadable", "malformed"]) {
    const calls = [];
    const pool = { query: async (sql) => { calls.push(sql); if (sql.includes("deployment_history")) return { rows: [{ id: 9, staging_url: "http://staging.example" }] }; if (sql.startsWith("SELECT id FROM dast_scans")) return { rows: [] }; if (sql.startsWith("INSERT INTO dast_scans")) return { rows: [{ id: 101 }] }; return { rows: [], rowCount: 1 }; } };
    const fakeFs = { mkdtempSync: () => "/tmp/dast-unit", existsSync: () => mode !== "missing", readFileSync: () => { if (mode === "unreadable") throw new Error("EACCES"); return "{"; }, rmSync() {} };
    await assert.rejects(() => runBaselineScan({ pool, projectId: 17, executionId: 44, targetUrl: "http://staging.example", userId: 3, runner: async () => {}, fsImpl: fakeFs }));
    assert.ok(calls.some((sql) => sql.includes("SET status='FAILED'")));
    assert.ok(!calls.some((sql) => sql.includes("status='COMPLETED'")));
  }
});

test("zero-finding on-disk report completes atomically without historical cleanup", async () => {
  const calls = [];
  const client = { query: async (sql) => { calls.push(sql); if (["BEGIN", "COMMIT"].includes(sql) || sql.startsWith("DELETE")) return { rows: [], rowCount: 1 }; if (sql.startsWith("SELECT COUNT")) return { rows: [{ total: 0, high: 0, medium: 0, low: 0, informational: 0, fingerprints: 0 }] }; if (sql.startsWith("UPDATE dast_scans SET status='COMPLETED'")) return { rows: [{ id: 101 }], rowCount: 1 }; throw new Error(`Unexpected client SQL: ${sql}`); }, release() { calls.push("RELEASE"); } };
  const pool = { query: async (sql) => { calls.push(sql); if (sql.includes("deployment_history")) return { rows: [{ id: 9, staging_url: "http://staging.example" }] }; if (sql.startsWith("SELECT id FROM dast_scans")) return { rows: [] }; if (sql.startsWith("INSERT INTO dast_scans")) return { rows: [{ id: 101 }] }; throw new Error(`Unexpected pool SQL: ${sql}`); }, connect: async () => client };
  const fakeFs = { mkdtempSync: () => "/tmp/dast-unit", existsSync: () => true, readFileSync: () => '{"site":[]}', rmSync() {} };
  const result = await runBaselineScan({ pool, projectId: 17, executionId: 44, targetUrl: "http://staging.example", userId: 3, runner: async () => {}, fsImpl: fakeFs });
  assert.deepEqual(result.summary, { total: 0, high: 0, medium: 0, low: 0, informational: 0 });
  assert.ok(calls.includes("COMMIT"));
});
