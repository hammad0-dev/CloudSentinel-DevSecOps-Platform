const assert = require("node:assert/strict");
const test = require("node:test");
const { persistSastEvidence } = require("../services/sastEvidence");

const issue = (severity = "MAJOR", suffix = "1") => ({
  rule: `rule-${suffix}`,
  severity,
  message: `message-${suffix}`,
  component: `src/${suffix}.js`,
  line: 1,
});
const coerce = (row, projectId) => [projectId, row.rule, row.severity, row.message, row.component, row.line];

function evidencePool({ verification, failInsert = false, completionRows = [{ id: 9 }] }) {
  const calls = [];
  const client = {
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (failInsert && sql.startsWith("INSERT INTO scan_results")) throw new Error("insert failed");
      if (sql.startsWith("SELECT COUNT(*)::int")) return { rows: [verification] };
      if (sql.startsWith("UPDATE scan_history")) return { rows: completionRows };
      return { rows: [] };
    },
    release: () => { calls.push({ sql: "RELEASE" }); },
  };
  return { pool: { connect: async () => client }, calls };
}

test("persists all SAST findings before marking the scan completed and linked", async () => {
  const { pool, calls } = evidencePool({
    verification: { total: 2, distinct_total: 2, critical: 0, high: 1, medium: 1, low: 0 },
  });
  const summary = await persistSastEvidence(pool, {
    projectId: 4,
    scanHistoryId: 9,
    issues: [issue("MAJOR", "a"), issue("MINOR", "b")],
    coerceIssueRow: coerce,
  });
  assert.equal(summary.total, 2);
  assert.equal(calls.filter(({ sql }) => sql.startsWith("INSERT INTO scan_results")).length, 2);
  assert.ok(calls.find(({ sql }) => sql.startsWith("UPDATE scan_history")));
  assert.equal(calls.at(-2).sql, "COMMIT");
});

test("rolls back a failed insert and never marks the SAST scan completed", async () => {
  const { pool, calls } = evidencePool({ verification: {}, failInsert: true });
  await assert.rejects(
    persistSastEvidence(pool, { projectId: 4, scanHistoryId: 9, issues: [issue()], coerceIssueRow: coerce }),
    /insert failed/
  );
  assert.ok(calls.some(({ sql }) => sql === "ROLLBACK"));
  assert.equal(calls.some(({ sql }) => sql.startsWith("UPDATE scan_history")), false);
});

test("rolls back count mismatch or duplicate evidence and never sets the linked marker", async () => {
  const { pool, calls } = evidencePool({
    verification: { total: 2, distinct_total: 1, critical: 0, high: 2, medium: 0, low: 0 },
  });
  await assert.rejects(
    persistSastEvidence(pool, { projectId: 4, scanHistoryId: 9, issues: [issue("MAJOR")], coerceIssueRow: coerce }),
    /persistence verification failed/
  );
  assert.ok(calls.some(({ sql }) => sql === "ROLLBACK"));
  assert.equal(calls.some(({ sql }) => sql.startsWith("UPDATE scan_history")), false);
});

test("accepts a verified zero-finding SAST scan", async () => {
  const { pool, calls } = evidencePool({
    verification: { total: 0, distinct_total: 0, critical: 0, high: 0, medium: 0, low: 0 },
  });
  const summary = await persistSastEvidence(pool, {
    projectId: 4,
    scanHistoryId: 9,
    issues: [],
    coerceIssueRow: coerce,
  });
  assert.deepEqual(summary, { total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  assert.ok(calls.find(({ sql }) => sql.startsWith("UPDATE scan_history")));
  assert.ok(calls.some(({ sql }) => sql === "COMMIT"));
});
test('persists independent SonarQube type and hotspot review without changing severity',async()=>{
 const {pool,calls}=evidencePool({verification:{total:2,distinct_total:2,critical:0,high:1,medium:0,low:1}});
 await persistSastEvidence(pool,{projectId:4,scanHistoryId:9,issues:[{...issue('MAJOR','css'),type:'CODE_SMELL'},{...issue('INFO','hotspot'),type:'SECURITY_HOTSPOT',status:'REVIEWED',resolution:'SAFE'}],coerceIssueRow:coerce});
 const rows=calls.filter(c=>c.sql.startsWith('INSERT INTO scan_results')).map(c=>c.params);
 assert.equal(rows[0][3],'MAJOR');assert.deepEqual(rows[0].slice(-2),['CODE_SMELL','NOT_APPLICABLE']);assert.deepEqual(rows[1].slice(-2),['SECURITY_HOTSPOT','SAFE']);
});
