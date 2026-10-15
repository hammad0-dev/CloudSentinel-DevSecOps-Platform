const assert = require("node:assert/strict");
const test = require("node:test");
const { resolvePipelineExecutionId } = require("../services/pipelineExecutionContext");

function poolWith(rows) {
  const calls = [];
  return {
    calls,
    pool: {
      query: async (sql, params) => {
        calls.push({ sql, params });
        return { rows };
      },
    },
  };
}

test("valid orchestrated scan context links to its running project execution", async () => {
  const mocked = poolWith([{ id: 42 }]);
  const value = await resolvePipelineExecutionId(
    mocked.pool,
    { id: 7, pipelineOrchestrator: true, pipelineExecutionId: 42 },
    12
  );
  assert.equal(value, 42);
  assert.deepEqual(mocked.calls[0].params, [42, 12]);
});

test("manual scan context remains unlinked without querying execution state", async () => {
  const mocked = poolWith([]);
  const value = await resolvePipelineExecutionId(mocked.pool, { id: 7 }, 12);
  assert.equal(value, null);
  assert.equal(mocked.calls.length, 0);
});

test("cross-project or non-running execution context is rejected", async () => {
  const mocked = poolWith([]);
  await assert.rejects(
    resolvePipelineExecutionId(
      mocked.pool,
      { id: 7, pipelineOrchestrator: true, pipelineExecutionId: 99 },
      12
    ),
    /does not belong/
  );
  assert.deepEqual(mocked.calls[0].params, [99, 12]);
});

test("an execution id without the internal orchestrator marker is rejected", async () => {
  const mocked = poolWith([{ id: 42 }]);
  await assert.rejects(
    resolvePipelineExecutionId(mocked.pool, { id: 7, pipelineExecutionId: 42 }, 12),
    /Invalid pipeline execution context/
  );
  assert.equal(mocked.calls.length, 0);
});