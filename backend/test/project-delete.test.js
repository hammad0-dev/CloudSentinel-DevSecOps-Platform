// Project delete with completed scans (migration 019 retention triggers): readable 409, never a raw 500.
const assert = require("node:assert/strict");
const test = require("node:test");
const dbPath = require.resolve("../db"), authPath = require.resolve("../middleware/auth"), routePath = require.resolve("../routes/projects");
const mock = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports, children: [], paths: [] }; };
test.afterEach(() => { for (const p of [dbPath, authPath, routePath]) delete require.cache[p]; });

function handler(onDelete) {
  const sql = [];
  const client = { query: async (q, args) => { sql.push(q); if (q.startsWith("SELECT id FROM projects")) return { rows: [{ id: 29 }] }; if (q.startsWith("DELETE")) return onDelete(q, args); return { rows: [] }; }, release() {} };
  mock(dbPath, { connect: async () => client, query: client.query });
  mock(authPath, (req, res, next) => next());
  const layer = require(routePath).stack.find(l => l.route?.path === "/:id" && l.route.methods.delete);
  return { h: layer.route.stack.at(-1).handle, sql };
}
async function call(h) { const out = {}; await h({ params: { id: "29" }, user: { id: 3 } }, { status(c) { out.status = c; return this; }, json(b) { out.body = b; return this; } }); return out; }

for (const code of ["COMPLETED_SCAN_EVIDENCE_IMMUTABLE", "COMPLETED_SCAN_RETENTION_REQUIRED", "ATTESTED_SCAN_RECORD_IMMUTABLE"]) {
  test(`delete refused by ${code} -> 409 with a readable message, rolled back`, async () => {
    const { h, sql } = handler(async () => { throw Object.assign(new Error(code), { code: "P0001" }); });
    const out = await call(h);
    assert.equal(out.status, 409);
    assert.match(out.body.error, /^This project can't be deleted because it has completed security scans/);
    assert.doesNotMatch(out.body.error, /IMMUTABLE|RETENTION|ATTESTED/);
    assert.ok(sql.includes("ROLLBACK"));
  });
}

test("unexpected database error -> generic 500 without the raw database message", async () => {
  const { h } = handler(async () => { throw new Error('relation "x" does not exist'); });
  const out = await call(h);
  assert.equal(out.status, 500); assert.doesNotMatch(out.body.error, /relation/);
});
