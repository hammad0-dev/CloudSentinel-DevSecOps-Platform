const assert = require("node:assert/strict");
const test = require("node:test");

const dbPath = require.resolve("../db");
const gitHelperPath = require.resolve("../services/gitHelper");
const deploymentPath = require.resolve("../services/deployment");

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

function clearMocks() {
  delete require.cache[deploymentPath];
  delete require.cache[dbPath];
  delete require.cache[gitHelperPath];
}

test.afterEach(clearMocks);

test("authorized ownership is enforced before deployment work begins", async () => {
  const queries = [];
  let cloneCalled = false;

  installMock(dbPath, {
    query: async (sql, params) => {
      queries.push({ sql, params });
      return { rows: [], rowCount: 0 };
    },
  });
  installMock(gitHelperPath, {
    resolveCloneUrl: () => "https://example.invalid/repo.git",
    gitCloneAsync: async () => { cloneCalled = true; },
  });

  const { deployProject } = require(deploymentPath);
  await assert.rejects(deployProject(42, 999), /not found or not accessible/);

  assert.equal(cloneCalled, false);
  assert.equal(queries.length, 1);
  assert.ok(queries[0].sql.includes("WHERE id = $1 AND user_id = $2"));
  assert.deepEqual(queries[0].params, [42, 999]);
});

test("unknown projects fail without writing deployment history", async () => {
  const queries = [];

  installMock(dbPath, {
    query: async (sql, params) => {
      queries.push({ sql, params });
      return { rows: [], rowCount: 0 };
    },
  });
  installMock(gitHelperPath, {
    resolveCloneUrl: () => { throw new Error("must not resolve"); },
    gitCloneAsync: async () => { throw new Error("must not clone"); },
  });

  const { deployProject } = require(deploymentPath);
  await assert.rejects(deployProject(999999, 7), /not found or not accessible/);
  assert.equal(queries.length, 1);
  assert.doesNotMatch(queries[0].sql, /deployment_history/);
});

test("missing or client-shaped identity values are rejected before querying", async () => {
  let queryCalled = false;
  installMock(dbPath, {
    query: async () => {
      queryCalled = true;
      return { rows: [] };
    },
  });
  installMock(gitHelperPath, {
    resolveCloneUrl: () => "",
    gitCloneAsync: async () => {},
  });

  const { deployProject } = require(deploymentPath);
  await assert.rejects(deployProject(12), /authenticated user/);
  await assert.rejects(deployProject(12, "7"), /authenticated user/);
  assert.equal(queryCalled, false);
});
