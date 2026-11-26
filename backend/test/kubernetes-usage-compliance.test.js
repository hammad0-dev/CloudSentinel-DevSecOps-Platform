// SRS FR-16.2 (resource usage from metrics-server) and FR-17.6 (compliance score from Kyverno policy reports).
const assert = require("node:assert/strict");
const test = require("node:test");
const u = require("../services/kubernetesUsage");
const { complianceScore, projectPolicies } = require("../services/kubernetesPolicy");

const ownedNs = { metadata: { name: "cloudsentinel-p-24", labels: { "app.kubernetes.io/managed-by": "cloudsentinel", "cloudsentinel.io/project-id": "24" } } };
const pool = { query: async () => ({ rows: [{ id: 24 }] }) };

test("CPU and memory quantities are parsed to millicores and MiB", () => {
  assert.equal(u.cpuMillicores("250m"), 250);
  assert.equal(u.cpuMillicores("2"), 2000);
  assert.equal(u.cpuMillicores("123456789n"), 123.456789);
  assert.equal(u.cpuMillicores("1500u"), 1.5);
  assert.equal(u.cpuMillicores("bogus"), null);
  assert.equal(u.memoryMiB("1048576Ki"), 1024);
  assert.equal(u.memoryMiB("512Mi"), 512);
  assert.equal(u.memoryMiB("1Gi"), 1024);
  assert.equal(u.memoryMiB(String(2 ** 20)), 1);
  assert.equal(u.memoryMiB("x"), null);
});

const nodeMetrics = { items: [{ metadata: { name: "minikube" }, usage: { cpu: "800m", memory: "4194304Ki" }, window: "20s" }] };
const nodes = { items: [{ metadata: { name: "minikube" }, status: { allocatable: { cpu: "8", memory: "16777216Ki" } } }] };
const podMetrics = { items: [
  { metadata: { name: "app-1", namespace: "cloudsentinel-p-24" }, containers: [{ usage: { cpu: "5m", memory: "30Mi" } }, { usage: { cpu: "1m", memory: "2Mi" } }] },
  { metadata: { name: "other", namespace: "kube-system" }, containers: [{ usage: { cpu: "99m", memory: "99Mi" } }] },
] };

test("usage: cluster from nodes, project pods only from the project namespace", async () => {
  const raw = async p => (p.endsWith("/nodes") ? nodeMetrics : podMetrics);
  const run = async args => (args[0] === "get" && args[1] === "namespace" ? ownedNs : nodes);
  const r = await u.projectUsage(pool, 5, "24", { run, raw });
  assert.equal(r.code, 200);
  assert.equal(r.body.status, "observed");
  assert.deepEqual(r.body.cluster, { nodes: 1, cpuMillicores: 800, memoryMiB: 4096, allocatableCpuMillicores: 8000, allocatableMemoryMiB: 16384, cpuPercent: 10, memoryPercent: 25 });
  assert.deepEqual(r.body.pods, [{ namespace: "cloudsentinel-p-24", name: "app-1", cpuMillicores: 6, memoryMiB: 32, containers: 2 }]);
  assert.deepEqual(r.body.project, { pods: 1, cpuMillicores: 6, memoryMiB: 32 });
});

test("usage: metrics API not served -> honest 'not available on this cluster' state, no numbers", async () => {
  const err = Object.assign(new Error("Error from server (NotFound): the server could not find the requested resource"), { stderr: "" });
  const r = await u.projectUsage(pool, 5, "24", { run: async () => ownedNs, raw: async () => { throw err; } });
  assert.equal(r.body.status, "metrics_unavailable");
  assert.match(r.body.reason, /^Not available on this cluster: metrics-server is not running on minikube/);
  assert.equal(r.body.cluster, undefined);
  const down = await u.projectUsage(pool, 5, "24", { run: async () => ownedNs, raw: async () => { throw new Error("connection refused"); } });
  assert.equal(down.body.status, "not_connected");
});

test("usage: unknown project and unowned namespace are refused before any metrics call", async () => {
  let called = false;
  const raw = async () => { called = true; return nodeMetrics; };
  const none = await u.projectUsage({ query: async () => ({ rows: [] }) }, 5, "24", { run: async () => ownedNs, raw });
  assert.equal(none.code, 404);
  const foreign = await u.projectUsage(pool, 5, "24", { run: async () => ({ metadata: { name: "cloudsentinel-p-24", labels: {} } }), raw });
  assert.equal(foreign.body.status, "not_connected");
  assert.equal(called, false);
});

test("compliance score = pass / (pass + fail + warn + error); skip not counted; no results -> null", () => {
  const c = complianceScore([{ pass: 14, fail: 1, warn: 0, error: 1, skip: 5 }, { pass: 2, fail: 0, warn: 0, error: 0, skip: 0 }]);
  assert.equal(c.evaluated, 18);
  assert.equal(c.score, 88.9);
  assert.equal(c.skip, 5);
  assert.equal(complianceScore([]).score, null);
  assert.equal(complianceScore([{ pass: 0, fail: 0, warn: 0, error: 0, skip: 3 }]).score, null);
  assert.equal(complianceScore([{ pass: 7, fail: 0, warn: 0, error: 0, skip: 0 }]).score, 100);
});

test("policy endpoint includes the compliance score; Kyverno missing stays 'kyverno_not_installed'", async () => {
  const reports = { items: [{ kind: "PolicyReport", results: [{ policy: "require-labels", result: "pass" }, { policy: "require-labels", result: "fail", resources: [{ kind: "Pod", name: "x", namespace: "cloudsentinel-p-24" }] }, { policy: "disallow-privileged", result: "pass" }] }] };
  const run = async args => {
    if (args[0] === "get" && args[1] === "namespace") return ownedNs;
    if (args[1] === "clusterpolicies") return { items: [{ metadata: { name: "require-labels" }, spec: { validationFailureAction: "Enforce", rules: [{}] } }] };
    if (args[1] === "policyreports") return reports;
    return { items: [] };
  };
  const r = await projectPolicies(pool, 5, "24", run);
  assert.equal(r.body.status, "observed");
  assert.equal(r.body.compliance.score, 66.7);
  assert.equal(r.body.compliance.fail, 1);
  const missing = Object.assign(new Error("error: the server doesn't have a resource type \"clusterpolicies\""), { stderr: "" });
  const none = await projectPolicies(pool, 5, "24", async args => { if (args[1] === "namespace") return ownedNs; throw missing; });
  assert.equal(none.body.status, "kyverno_not_installed");
  assert.equal(none.body.compliance, undefined);
});
