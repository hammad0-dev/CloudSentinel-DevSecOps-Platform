const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const dbPath = require.resolve("../db");
const orchestratorPath = require.resolve("../services/orchestrator");
const webhooksPath = require.resolve("../routes/webhooks");

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
  delete require.cache[webhooksPath];
  delete require.cache[orchestratorPath];
  delete require.cache[dbPath];
}

test.afterEach(clearMocks);

function signatureFor(rawBody, secret) {
  return "sha256=" + crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");
}

function createHarness({ projects, active = false }) {
  const pipelineCalls = [];
  const queries = [];

  installMock(dbPath, {
    query: async (sql, params) => {
      queries.push({ sql, params });
      if (sql.includes("FROM projects")) {
        return { rows: projects, rowCount: projects.length };
      }
      if (sql.includes("status IN")) {
        return active
          ? { rows: [{ id: 88 }], rowCount: 1 }
          : { rows: [], rowCount: 0 };
      }
      if (sql.includes("INSERT INTO pipeline_executions")) {
        return { rows: [{ id: 100 }], rowCount: 1 };
      }
      throw new Error("Unexpected query");
    },
  });
  installMock(orchestratorPath, {
    runPipeline: (...args) => {
      pipelineCalls.push(args);
      return Promise.resolve();
    },
  });

  const router = require(webhooksPath);
  const layer = router.stack.find((item) => item.route?.path === "/github");
  return {
    handler: layer.route.stack[0].handle,
    pipelineCalls,
    queries,
  };
}

async function invoke(handler, {
  event = "push",
  repository = "example/owned-project",
  secret,
  signature,
  includeSignature = true,
  rawBody,
} = {}) {
  const body = { repository: { full_name: repository } };
  const exactRawBody = rawBody === undefined ? JSON.stringify(body) : rawBody;
  const headers = { "x-github-event": event };

  if (includeSignature) {
    headers["x-hub-signature-256"] =
      signature || signatureFor(exactRawBody, secret);
  }

  const req = { body, rawBody: Buffer.from(exactRawBody), headers };
  const response = {};
  const res = {
    status(code) {
      response.status = code;
      return this;
    },
    json(payload) {
      response.payload = payload;
      return this;
    },
  };

  await handler(req, res);
  return response;
}

function project(id, userId, repoUrl, secret) {
  return {
    id,
    user_id: userId,
    repo_url: repoUrl,
    webhook_secret: secret,
  };
}

test("A: valid signed push triggers the intended pipeline", async () => {
  const item = project(42, 7, "https://github.com/example/owned-project", "secret-a");
  const harness = createHarness({ projects: [item] });
  const response = await invoke(harness.handler, { secret: "secret-a" });

  assert.equal(response.status, 202);
  assert.equal(response.payload.executionId, 100);
  assert.deepEqual(harness.pipelineCalls, [[100, 42, 7]]);
  assert.deepEqual(harness.queries[0].params, ["https://github.com/example/owned-project"]);
});

test("B: invalid signature returns 401 without pipeline execution", async () => {
  const harness = createHarness({
    projects: [project(42, 7, "https://github.com/example/owned-project", "secret-a")],
  });
  const response = await invoke(harness.handler, {
    secret: "wrong-secret",
  });

  assert.equal(response.status, 401);
  assert.deepEqual(harness.pipelineCalls, []);
  assert.equal(harness.queries.length, 1);
});

test("C and D: duplicate repository registrations resolve by their distinct secrets", async () => {
  const projects = [
    project(42, 7, "https://github.com/example/owned-project", "secret-a"),
    project(84, 9, "https://github.com/example/owned-project.git", "secret-b"),
  ];

  let harness = createHarness({ projects });
  let response = await invoke(harness.handler, { secret: "secret-a" });
  assert.equal(response.status, 202);
  assert.deepEqual(harness.pipelineCalls, [[100, 42, 7]]);

  clearMocks();
  harness = createHarness({ projects });
  response = await invoke(harness.handler, { secret: "secret-b" });
  assert.equal(response.status, 202);
  assert.deepEqual(harness.pipelineCalls, [[100, 84, 9]]);
});

test("E: signed payload with a mismatched repository identity is rejected", async () => {
  const harness = createHarness({
    projects: [project(42, 7, "https://github.com/example/project-a", "secret-a")],
  });
  const response = await invoke(harness.handler, {
    repository: "example/project-b",
    secret: "secret-a",
  });

  assert.equal(response.status, 401);
  assert.deepEqual(harness.pipelineCalls, []);
});

test("F: similar repository names cannot be confused", async () => {
  const harness = createHarness({
    projects: [
      project(42, 7, "https://github.com/example/repo", "secret-a"),
      project(84, 9, "https://github.com/example/repo-extra", "secret-b"),
    ],
  });
  const response = await invoke(harness.handler, {
    repository: "example/repo",
    secret: "secret-b",
  });

  assert.equal(response.status, 401);
  assert.deepEqual(harness.pipelineCalls, []);
});

test("G: missing signature returns 401 before database access", async () => {
  const harness = createHarness({ projects: [] });
  const response = await invoke(harness.handler, {
    includeSignature: false,
  });

  assert.equal(response.status, 401);
  assert.deepEqual(harness.pipelineCalls, []);
  assert.equal(harness.queries.length, 0);
});

test("H: project-scoped concurrency rejection remains intact", async () => {
  const harness = createHarness({
    projects: [project(42, 7, "https://github.com/example/owned-project", "secret-a")],
    active: true,
  });
  const response = await invoke(harness.handler, { secret: "secret-a" });

  assert.equal(response.status, 409);
  assert.deepEqual(harness.pipelineCalls, []);
  assert.deepEqual(harness.queries[1].params, [42]);
});

test("I: signed ping and unsupported events never start a pipeline", async () => {
  let harness = createHarness({
    projects: [project(42, 7, "https://github.com/example/owned-project", "secret-a")],
  });
  let response = await invoke(harness.handler, {
    event: "ping",
    secret: "secret-a",
  });
  assert.equal(response.status, 200);
  assert.equal(response.payload.message, "Pong");
  assert.deepEqual(harness.pipelineCalls, []);

  clearMocks();
  harness = createHarness({
    projects: [project(42, 7, "https://github.com/example/owned-project", "secret-a")],
  });
  response = await invoke(harness.handler, {
    event: "issues",
    secret: "secret-a",
  });
  assert.equal(response.status, 200);
  assert.match(response.payload.message, /Ignored/);
  assert.deepEqual(harness.pipelineCalls, []);
});

test("J: an existing .git repository URL remains compatible", async () => {
  const harness = createHarness({
    projects: [project(42, 7, "https://github.com/example/owned-project.git", "secret-a")],
  });
  const response = await invoke(harness.handler, {
    repository: "Example/Owned-Project",
    secret: "secret-a",
  });

  assert.equal(response.status, 202);
  assert.deepEqual(harness.pipelineCalls, [[100, 42, 7]]);
});

test("signature verification uses the exact raw body", async () => {
  const harness = createHarness({
    projects: [project(42, 7, "https://github.com/example/owned-project", "secret-a")],
  });
  const body = { repository: { full_name: "example/owned-project" } };
  const differentlyFormattedRawBody = JSON.stringify(body, null, 2);
  const compactSignature = signatureFor(JSON.stringify(body), "secret-a");
  const response = await invoke(harness.handler, {
    secret: "secret-a",
    signature: compactSignature,
    rawBody: differentlyFormattedRawBody,
  });

  assert.equal(response.status, 401);
  assert.deepEqual(harness.pipelineCalls, []);
});

test("ambiguous matching secrets are rejected without selecting a row", async () => {
  const harness = createHarness({
    projects: [
      project(42, 7, "https://github.com/example/owned-project", "shared-secret"),
      project(84, 9, "https://github.com/example/owned-project.git", "shared-secret"),
    ],
  });
  const response = await invoke(harness.handler, { secret: "shared-secret" });

  assert.equal(response.status, 409);
  assert.deepEqual(harness.pipelineCalls, []);
});