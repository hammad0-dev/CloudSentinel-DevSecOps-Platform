const assert = require("node:assert/strict");
const test = require("node:test");

const dbPath = require.resolve("../db");
const authPath = require.resolve("../middleware/auth");
const projectsPath = require.resolve("../routes/projects");
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

function clearMocks() {
  delete require.cache[projectsPath];
  delete require.cache[authPath];
  delete require.cache[dbPath];
  delete require.cache[axiosPath];
}

test.afterEach(clearMocks);

function secretBearingProject() {
  return {
    id: 42,
    name: "demo",
    repo_url: "https://github.com/example/demo",
    language: "JavaScript",
    framework: "Express.js",
    database_tech: "PostgreSQL",
    is_private: true,
    webhook_id: "123",
    webhook_secret: "must-not-leak",
    github_token: "ghp_must_not_leak",
    target_url: "http://staging.example",
    created_at: "2026-10-11T00:00:00.000Z",
  };
}

function loadRouter(query, axiosMock) {
  installMock(authPath, (req, _res, next) => {
    req.user = { id: 7 };
    next();
  });
  installMock(dbPath, { query });
  if (axiosMock) installMock(axiosPath, axiosMock);
  return require(projectsPath);
}

function routeHandler(router, path, method) {
  const layer = router.stack.find((item) => item.route?.path === path && item.route.methods[method]);
  assert.ok(layer, `expected ${method.toUpperCase()} ${path} route`);
  return layer.route.stack.at(-1).handle;
}

async function invoke(handler, req = {}) {
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
  await handler({ user: { id: 7 }, params: {}, ...req }, res);
  return response;
}

function projectAndScanMock(sql) {
  if (sql.includes("FROM projects")) return { rows: [secretBearingProject()] };
  if (sql.includes("FROM scan_history")) return { rows: [] };
  throw new Error("Unexpected query: " + sql);
}

test("project list responses never expose webhook secrets or GitHub tokens", async () => {
  const router = loadRouter(async (sql) => projectAndScanMock(sql));
  const response = await invoke(routeHandler(router, "/", "get"));
  const body = JSON.stringify(response.payload);

  assert.equal(response.payload.projects[0].webhook_secret, undefined);
  assert.equal(response.payload.projects[0].github_token, undefined);
  assert.equal(body.includes("must-not-leak"), false);
  assert.equal(body.includes("ghp_must_not_leak"), false);
});

test("project detail responses never expose webhook secrets or GitHub tokens", async () => {
  const router = loadRouter(async (sql) => projectAndScanMock(sql));
  const response = await invoke(routeHandler(router, "/:id", "get"), { params: { id: "42" } });
  const body = JSON.stringify(response.payload);

  assert.equal(response.payload.project.webhook_secret, undefined);
  assert.equal(response.payload.project.github_token, undefined);
  assert.equal(body.includes("must-not-leak"), false);
  assert.equal(body.includes("ghp_must_not_leak"), false);
});
test("project creation response never exposes webhook secrets or GitHub tokens", async () => {
  const router = loadRouter(
    async (sql) => {
      if (sql.startsWith("INSERT INTO projects")) return { rows: [secretBearingProject()] };
      throw new Error("Unexpected query: " + sql);
    },
    {
      get: async (url) => {
        if (url.includes("/contents/package.json")) {
          return { data: { content: Buffer.from('{"dependencies":{"express":"1"}}').toString("base64") } };
        }
        if (url.includes("/contents/")) throw new Error("not found");
        return { data: { language: "JavaScript", private: false, name: "demo", full_name: "example/demo" } };
      },
    }
  );
  const response = await invoke(routeHandler(router, "/", "post"), {
    body: { name: "demo", repoUrl: "https://github.com/example/demo" },
  });
  const body = JSON.stringify(response.payload);

  assert.equal(response.status, 201);
  assert.equal(response.payload.project.webhook_secret, undefined);
  assert.equal(response.payload.project.github_token, undefined);
  assert.equal(body.includes("must-not-leak"), false);
  assert.equal(body.includes("ghp_must_not_leak"), false);
});