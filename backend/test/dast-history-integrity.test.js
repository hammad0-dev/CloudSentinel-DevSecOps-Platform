const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "..");
const dbPath = require.resolve("../db");
const authPath = require.resolve("../middleware/auth");
const routePath = require.resolve("../routes/dast");

function mock(modulePath, exports) {
  require.cache[modulePath] = { id: modulePath, filename: modulePath, loaded: true, exports, children: [], paths: [] };
}

function clear() {
  delete require.cache[dbPath];
  delete require.cache[authPath];
  delete require.cache[routePath];
}

function getHandler(db) {
  mock(dbPath, { query: db });
  mock(authPath, (req, res, next) => next());
  const router = require(routePath);
  return router.stack.find((layer) => layer.route?.path === "/:projectId" && layer.route.methods.get).route.stack[1].handle;
}

async function call(handler, { projectId = "17", scanId } = {}) {
  const out = {};
  const req = { params: { projectId }, query: scanId === undefined ? {} : { scanId: String(scanId) }, user: { id: 3 } };
  const res = { status(code) { out.status = code; return this; }, json(body) { out.body = body; return this; } };
  await handler(req, res);
  return out;
}

test.afterEach(clear);

test("Migration 011 preserves legacy metadata and adds project-aware scan integrity", () => {
  const migration = fs.readFileSync(path.join(root, "migrations/011_dast_historical_integrity.sql"), "utf8");
  assert.match(migration, /ADD COLUMN IF NOT EXISTS scan_mode VARCHAR\(20\)/);
  assert.match(migration, /ADD COLUMN IF NOT EXISTS scan_group_id UUID/);
  assert.match(migration, /ADD COLUMN IF NOT EXISTS finding_fingerprint CHAR\(64\)/);
  assert.match(migration, /FOREIGN KEY \(scan_id, project_id\) REFERENCES dast_scans \(id, project_id\)/);
  assert.match(migration, /ON DELETE CASCADE NOT VALID/);
  assert.match(migration, /dast_findings_scan_fingerprint_uidx/);
  assert.doesNotMatch(migration, /UPDATE\s+dast_/i);
});

test("DAST route keeps history and returns only the requested scan's findings", async () => {
  const handler = getHandler(async (sql, params) => {
    if (sql.includes("FROM projects")) return { rows: [{ id: 17, target_url: "http://staging" }] };
    if (sql.includes("FROM dast_scans WHERE project_id = $1 AND id = $2")) {
      assert.deepEqual(params, [17, 13]);
      return { rows: [{ id: 13, status: "COMPLETED", total_findings: 1 }] };
    }
    if (sql.includes("FROM dast_scans WHERE project_id = $1 ORDER BY started_at DESC")) {
      return { rows: [{ id: 13 }, { id: 12 }] };
    }
    if (sql.includes("FROM dast_findings")) {
      assert.deepEqual(params, [17, 13]);
      return { rows: [{ id: 101, alert: "current-only", severity: "LOW" }] };
    }
    throw new Error(`Unexpected SQL: ${sql}`);
  });
  const out = await call(handler, { scanId: 13 });
  assert.equal(out.status, undefined);
  assert.equal(out.body.latestScan.id, 13);
  assert.deepEqual(out.body.history.map((scan) => scan.id), [13, 12]);
  assert.deepEqual(out.body.findings, [{ id: 101, alert: "current-only", severity: "LOW" }]);
});

test("zero-finding scans retain an empty result rather than project-wide findings", async () => {
  const handler = getHandler(async (sql) => {
    if (sql.includes("FROM projects")) return { rows: [{ id: 17, target_url: "http://staging" }] };
    if (sql.includes("FROM dast_scans WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1")) return { rows: [{ id: 12, status: "COMPLETED", total_findings: 0 }] };
    if (sql.includes("FROM dast_scans WHERE project_id = $1 ORDER BY started_at DESC")) return { rows: [{ id: 12 }] };
    if (sql.includes("FROM dast_findings")) return { rows: [] };
    throw new Error(`Unexpected SQL: ${sql}`);
  });
  const out = await call(handler);
  assert.equal(out.body.latestScan.id, 12);
  assert.deepEqual(out.body.findings, []);
  assert.equal(out.body.summary.total, 0);
});

test("route rejects cross-project scan selection before returning findings", async () => {
  const handler = getHandler(async (sql) => sql.includes("FROM projects") ? { rows: [] } : (() => { throw new Error("should not query scans"); })());
  const out = await call(handler, { scanId: 13 });
  assert.equal(out.status, 404);
});

test("retry cleanup is scoped to the newly created scan, never the whole project", () => {
  const source = fs.readFileSync(path.join(root, "services/dastBaselineScanner.js"), "utf8");
  assert.match(source, /DELETE FROM dast_findings WHERE project_id = \$1 AND scan_id = \$2/);
  assert.doesNotMatch(source, /DELETE FROM dast_findings WHERE project_id = \$1"/);
});

test("unified report continues to select DAST detail by exact scan id", () => {
  const source = fs.readFileSync(path.join(root, "routes/reports.js"), "utf8");
  assert.match(source, /detail\(scans\.dast,"dast_findings","scan_id"/);
});
