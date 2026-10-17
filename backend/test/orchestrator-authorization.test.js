const assert = require("node:assert/strict");
const test = require("node:test");

const dbPath = require.resolve("../db");
const deploymentPath = require.resolve("../services/deployment");
const orchestratorPath = require.resolve("../services/orchestrator");
const axiosPath = require.resolve("axios");

function installMock(modulePath, exports) {
  require.cache[modulePath] = {
    id: modulePath,
    filename: modulePath,
    loaded: true,
    exports,
    children: [],
    paths: [],
  };
}

test.afterEach(() => {
  delete require.cache[orchestratorPath];
  delete require.cache[deploymentPath];
  delete require.cache[dbPath];
  delete require.cache[axiosPath];
});

test("pipeline forwards its trusted user identity to deployment", async () => {
  const deployCalls = [];
  const databaseCalls = [];
  process.env.JWT_SECRET = process.env.JWT_SECRET || "authorization-test-secret";

  installMock(dbPath, {
    query: async (sql, params) => {
      databaseCalls.push({ sql, params });
      if (sql.includes("FROM scan_history sh")) return { rows: [{ total_issues: 0, critical: 0, high: 0, medium: 0, low: 0, persisted_total: 0, distinct_total: 0, security_critical:0,security_high:0,hotspots_pending:0,unknown_types:0,persisted_critical: 0, persisted_high: 0, persisted_medium: 0, persisted_low: 0 }], rowCount: 1 };
      if (sql.includes("SELECT critical")) {
        return { rows: [{ critical: 0 }], rowCount: 1 };
      }
      if (sql.includes("SELECT target_url")) {
        return { rows: [{ target_url: null }], rowCount: 1 };
      }
      return { rows: [], rowCount: 1 };
    },
  });
  installMock(deploymentPath, {
    deployProject: async (...args) => {
      deployCalls.push(args);
      return { stagingUrl: "http://staging.invalid" };
    },
  });
  installMock(axiosPath, {
    post: async () => ({ data: {} }),
  });

  const { runPipeline } = require(orchestratorPath);
  await runPipeline(100, 42, 7);

  assert.deepEqual(deployCalls, [[42, 7, { executionId: 100, attempt: 1 }]]);
  assert.ok(
    databaseCalls.some(({ sql, params }) =>
      sql.includes("status = 'COMPLETED'") && params[0] === 100
    )
  );
});

test("failed deployment cannot use stale target URL, trigger DAST, or complete pipeline", async () => {
  const databaseCalls = [];
  const httpCalls = [];
  let deployAttempts = 0;
  process.env.JWT_SECRET = process.env.JWT_SECRET || "authorization-test-secret";

  installMock(dbPath, {
    query: async (sql, params) => {
      databaseCalls.push({ sql, params });
      if (sql.includes("FROM scan_history sh")) return { rows: [{ total_issues: 0, critical: 0, high: 0, medium: 0, low: 0, persisted_total: 0, distinct_total: 0, security_critical:0,security_high:0,hotspots_pending:0,unknown_types:0,persisted_critical: 0, persisted_high: 0, persisted_medium: 0, persisted_low: 0 }], rowCount: 1 }; if (sql.includes("SELECT critical")) return { rows: [{ critical: 0 }], rowCount: 1 };
      if (sql.includes("SELECT target_url")) return { rows: [{ target_url: "http://stale-previous-deployment.invalid" }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    },
  });
  installMock(deploymentPath, {
    deployProject: async () => { deployAttempts += 1; throw new Error("current rollout failed"); },
  });
  installMock(axiosPath, {
    post: async url => { httpCalls.push(url); return { data: {} }; },
  });

  const originalSetTimeout = global.setTimeout;
  global.setTimeout = callback => { callback(); return 0; };
  try {
    const { runPipeline } = require(orchestratorPath);
    await runPipeline(101, 42, 7);
  } finally {
    global.setTimeout = originalSetTimeout;
  }

  assert.equal(deployAttempts, 2);
  assert.equal(httpCalls.some(url => url.includes("/api/dast/scan/")), false);
  assert.equal(databaseCalls.some(call => call.sql.includes("SELECT target_url")), false);
  assert.equal(databaseCalls.some(call => call.sql.includes("UPDATE pipeline_executions SET status = 'COMPLETED'")), false);
  assert.ok(databaseCalls.some(call => call.sql.includes("status = 'ERROR'") && String(call.params[0]).includes("current rollout failed")));
});


test("critical image-security rejection is not retried and suppresses DAST", async () => {
  const databaseCalls = [];
  const httpCalls = [];
  let deployAttempts = 0;
  process.env.JWT_SECRET = process.env.JWT_SECRET || "authorization-test-secret";
  installMock(dbPath, { query: async (sql, params) => {
    databaseCalls.push({ sql, params });
    if (sql.includes("FROM scan_history sh")) return { rows: [{ total_issues: 0, critical: 0, high: 0, medium: 0, low: 0, persisted_total: 0, distinct_total: 0, security_critical:0,security_high:0,hotspots_pending:0,unknown_types:0,persisted_critical: 0, persisted_high: 0, persisted_medium: 0, persisted_low: 0 }], rowCount: 1 }; if (sql.includes("SELECT critical")) return { rows: [{ critical: 0 }], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }});
  installMock(deploymentPath, { deployProject: async () => {
    deployAttempts += 1;
    const error = new Error("critical image finding");
    error.code = "IMAGE_SECURITY_GATE_BLOCKED";
    error.nonRetryable = true;
    throw error;
  }});
  installMock(axiosPath, { post: async url => { httpCalls.push(url); return { data: {} }; }});
  const { runPipeline } = require(orchestratorPath);
  await runPipeline(102, 42, 7);
  assert.equal(deployAttempts, 1);
  assert.equal(httpCalls.some(url => url.includes("/api/dast/scan/")), false);
  assert.equal(databaseCalls.some(call => call.sql.includes("UPDATE pipeline_executions SET status = 'COMPLETED'")), false);
  assert.ok(databaseCalls.some(call => call.sql.includes("ERROR") && String(call.params[0]).includes("critical image finding")));
});

test("orchestrated scan requests carry the trusted execution claim while pipeline behavior remains normal", async () => {
  const jwt = require("jsonwebtoken");
  const httpCalls = [];
  process.env.JWT_SECRET = "execution-linkage-test-secret";
  installMock(dbPath, {
    query: async (sql) => {
      if (sql.includes("FROM scan_history sh")) return { rows: [{ total_issues: 0, critical: 0, high: 0, medium: 0, low: 0, persisted_total: 0, distinct_total: 0, security_critical:0,security_high:0,hotspots_pending:0,unknown_types:0,persisted_critical: 0, persisted_high: 0, persisted_medium: 0, persisted_low: 0 }], rowCount: 1 }; if (sql.includes("SELECT critical")) return { rows: [{ critical: 0 }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    },
  });
  installMock(deploymentPath, {
    deployProject: async () => ({ stagingUrl: "http://staging.invalid" }),
  });
  installMock(axiosPath, {
    post: async (url, _body, options) => {
      httpCalls.push({ url, options });
      return { data: {} };
    },
  });

  const { runPipeline } = require(orchestratorPath);
  await runPipeline(120, 42, 7);

  assert.equal(httpCalls.length, 4);
  for (const call of httpCalls) {
    const token = call.options.headers.Authorization.slice("Bearer ".length);
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    assert.equal(payload.id, 7);
    assert.equal(payload.pipelineExecutionId, 120);
    assert.equal(payload.pipelineOrchestrator, true);
  }
});
