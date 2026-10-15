const assert = require("node:assert/strict");
const test = require("node:test");

const dbPath = require.resolve("../db");
const orchestratorPath = require.resolve("../services/orchestrator");

function installDb(query) {
  require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: { query } };
  delete require.cache[orchestratorPath];
  return require(orchestratorPath).checkCriticalFindings;
}

test.afterEach(() => {
  delete require.cache[orchestratorPath];
  delete require.cache[dbPath];
});

const validZero = {
  total_issues: 0, critical: 0, high: 0, medium: 0, low: 0,
  persisted_total: 0, distinct_total: 0,
  persisted_critical: 0, persisted_high: 0, persisted_medium: 0, persisted_low: 0,
};

test("SAST gate fails closed when the exact execution has no completed linked scan", async () => {
  const check = installDb(async () => ({ rows: [] }));
  const result = await check(12, 55, "SAST");
  assert.deepEqual(result, { evidenceFound: false, hasCritical: true, evidenceConsistent: false });
});

test("SAST gate rejects count mismatch and duplicate evidence", async () => {
  const check = installDb(async () => ({ rows: [{ ...validZero, total_issues: 1, persisted_total: 1, distinct_total: 0, persisted_high: 1 }] }));
  const result = await check(12, 55, "SAST");
  assert.equal(result.evidenceFound, true);
  assert.equal(result.evidenceConsistent, false);
});

test("SAST gate uses only the requested execution and accepts a verified zero-finding scan", async () => {
  let parameters;
  const check = installDb(async (_sql, params) => {
    parameters = params;
    return { rows: [validZero] };
  });
  const result = await check(12, 55, "SAST");
  assert.deepEqual(parameters, [12, 55]);
  assert.deepEqual(result, { evidenceFound: true, hasCritical: false, evidenceConsistent: true });
});
