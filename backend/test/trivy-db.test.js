// Trivy DB warm-up and --skip-db-update decision for the image scan. node --test test/trivy-db.test.js
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("fs");
const os = require("os");
const path = require("path");
const trivyDb = require("../services/trivyDb");

function cache(meta, { db = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cs-trivy-db-"));
  fs.mkdirSync(path.join(dir, "db"));
  if (meta !== undefined) fs.writeFileSync(path.join(dir, "db", "metadata.json"), typeof meta === "string" ? meta : JSON.stringify(meta));
  if (db) fs.writeFileSync(path.join(dir, "db", "trivy.db"), "x");
  return dir;
}
const NOW = Date.parse("2026-11-26T12:00:00Z");
const env = (dir, extra = {}) => ({ IMAGE_TRIVY_CACHE_DIR: dir, ...extra });

test("a fresh DB adds --skip-db-update (and the explicit cache dir)", () => {
  const dir = cache({ DownloadedAt: "2026-11-26T06:00:00Z", NextUpdate: "2026-11-26T19:00:00Z" });
  assert.deepEqual(trivyDb.imageScanArgs(env(dir), NOW), ["--cache-dir", dir, "--skip-db-update"]);
  assert.equal(trivyDb.dbStatus(env(dir), NOW).fresh, true);
});

test("an old, missing, unreadable or future-dated DB is never skipped", () => {
  const cases = [
    cache({ DownloadedAt: "2026-11-23T12:00:00Z" }),           // 72 h old > 48 h
    cache(undefined),                                         // no metadata
    cache("{not json"),                                       // unreadable metadata
    cache({ DownloadedAt: "2026-11-26T06:00:00Z" }, { db: false }), // metadata without DB file
    cache({ DownloadedAt: "2026-12-30T00:00:00Z" }),          // clock skew / tampered
    cache({}),                                                // no DownloadedAt
  ];
  for (const dir of cases) assert.deepEqual(trivyDb.imageScanArgs(env(dir), NOW), ["--cache-dir", dir], dir);
});

test("TRIVY_DB_MAX_AGE_HOURS controls the limit; 0 always lets Trivy update", () => {
  const dir = cache({ DownloadedAt: "2026-11-26T06:00:00Z" });   // 6 h old
  assert.equal(trivyDb.dbStatus(env(dir, { TRIVY_DB_MAX_AGE_HOURS: "4" }), NOW).fresh, false);
  assert.equal(trivyDb.dbStatus(env(dir, { TRIVY_DB_MAX_AGE_HOURS: "0" }), NOW).fresh, false);
  assert.equal(trivyDb.dbStatus(env(dir, { TRIVY_DB_MAX_AGE_HOURS: "12" }), NOW).fresh, true);
});

test("default cache dir follows the Trivy install (snap vs XDG)", () => {
  assert.equal(trivyDb.cacheDir({ TRIVY_CMD: "/snap/bin/trivy" }), path.join(os.homedir(), "snap/trivy/current/.cache/trivy"));
  assert.equal(trivyDb.cacheDir({ TRIVY_CMD: "trivy", XDG_CACHE_HOME: "/x" }), "/x/trivy");
});

test("warm runs trivy --download-db-only and reports the result; the warmer can be disabled", async () => {
  const dir = cache({ DownloadedAt: new Date().toISOString() });
  const calls = [], logs = [];
  const r = await trivyDb.warm({ env: env(dir, { TRIVY_CMD: "trivy" }), runner: async (cmd, args) => { calls.push([cmd, ...args]); return { code: 0, ms: 5 }; }, log: e => logs.push(e) });
  assert.deepEqual(calls[0], ["trivy", "image", "--download-db-only", "--quiet", "--cache-dir", dir]);
  assert.equal(r.status.fresh, true);
  assert.equal(logs[0].event, "trivy_db_warm");
  let ran = 0;
  const stop = trivyDb.startWarmer({ env: { TRIVY_DB_WARM: "off" }, runner: async () => { ran += 1; return { code: 0 }; } });
  stop();
  assert.equal(ran, 0);
});

test("the image scan passes --skip-db-update only when the DB is fresh", async () => {
  const { scanContainerImage } = require("../services/imageVulnerabilityScan");
  const scan = async (dir) => {
    const calls = [];
    const saved = process.env.IMAGE_TRIVY_CACHE_DIR;
    process.env.IMAGE_TRIVY_CACHE_DIR = dir;
    try {
      await scanContainerImage({ pool: { query: async (sql) => (sql.includes("INSERT INTO image_scans") ? { rows: [{ id: 1 }] } : { rows: [] }) },
        execute: async (...a) => { calls.push(a); return JSON.stringify({ Results: [] }); }, cwd: "/tmp", projectId: 4, pipelineExecutionId: 9, deploymentAttempt: 1, imageTag: "cloudsentinel-p4:run-9" });
    } finally { if (saved === undefined) delete process.env.IMAGE_TRIVY_CACHE_DIR; else process.env.IMAGE_TRIVY_CACHE_DIR = saved; }
    return calls[0][2];
  };
  const fresh = await scan(cache({ DownloadedAt: new Date().toISOString() }));
  assert.ok(fresh.includes("--skip-db-update"));
  assert.equal(fresh[fresh.length - 1], "cloudsentinel-p4:run-9");
  const stale = await scan(cache({ DownloadedAt: "2020-01-01T00:00:00Z" }));
  assert.equal(stale.includes("--skip-db-update"), false);
});
