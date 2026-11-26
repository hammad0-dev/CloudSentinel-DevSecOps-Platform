#!/usr/bin/env node
// End-to-end smoke test: register fixtures, trigger the pipeline exactly like a GitHub
// push webhook, poll pipeline_executions, and print per-stage results.
//
// Env:
//   E2E_ENV_FILE              dotenv file with the vars below (default ~/.cloudsentinel-e2e.env)
//   E2E_EMAIL, E2E_PASSWORD   login of an existing CloudSentinel user (required)
//   E2E_API                   backend base URL (default http://127.0.0.1:${PORT||3000})
//   E2E_PYTHON_REPO           GitHub URL of the Python fixture repo
//   E2E_NODE_REPO             GitHub URL of the Node fixture repo
//   E2E_PYTHON_CLEAN_REPO     GitHub URL of the clean Python fixture repo
//   E2E_NODE_CLEAN_REPO       GitHub URL of the clean Node fixture repo (test-fixtures/cloudsentinel-test-node-clean)
//   E2E_DEMO_FORMS_REPO       GitHub URL of the DAST demo app (default: the public mirror of
//                             demo/forms-app, https://github.com/hammad0-dev/cloudsentinel-demo-forms)
//   E2E_GITHUB_TOKEN          optional, for private fixture repos
//   E2E_TIMEOUT_MIN           per-app timeout in minutes (default 45)
// Usage: node scripts/e2e-smoke.js [python|node|python-clean|node-clean|demo-forms ...]
"use strict";
const path = require("path");
const crypto = require("crypto");
const backend = path.join(__dirname, "..", "backend");
const req = (m) => require(require.resolve(m, { paths: [backend] }));
req("dotenv").config({ path: process.env.E2E_ENV_FILE || path.join(require("os").homedir(), ".cloudsentinel-e2e.env") });
req("dotenv").config({ path: process.env.BACKEND_ENV_FILE || path.join(backend, ".env") });
const axios = req("axios");
const pool = require(path.join(backend, "db"));

const API = (process.env.E2E_API || `http://127.0.0.1:${process.env.PORT || 3000}`).replace(/\/$/, "");
const APPS = {
  python: { name: "e2e-python-flask", repo: process.env.E2E_PYTHON_REPO },
  node: { name: "e2e-node-express", repo: process.env.E2E_NODE_REPO },
  "python-clean": { name: "e2e-python-clean", repo: process.env.E2E_PYTHON_CLEAN_REPO },
  "node-clean": { name: "e2e-node-clean", repo: process.env.E2E_NODE_CLEAN_REPO },
  "demo-forms": { name: "e2e-demo-forms", repo: process.env.E2E_DEMO_FORMS_REPO || "https://github.com/hammad0-dev/cloudsentinel-demo-forms" },
};
const DONE = ["COMPLETED", "STAGE_FAILED", "ERROR", "NOT_ADMITTED"];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const secs = (a, b) => (a && b ? Math.round((new Date(b) - new Date(a)) / 1000) : "-");
const fail = (msg) => { console.error("e2e: " + msg); process.exit(2); };

async function login() {
  const { E2E_EMAIL: email, E2E_PASSWORD: password } = process.env;
  if (!email || !password) fail("set E2E_EMAIL and E2E_PASSWORD");
  const r = await axios.post(`${API}/api/auth/login`, { email, password });
  const { id } = JSON.parse(Buffer.from(r.data.token.split(".")[1], "base64url"));
  return { token: r.data.token, userId: id };
}

async function ensureProject(auth, app) {
  if (!app.repo) fail(`missing repo URL for ${app.name} (E2E_PYTHON_REPO / E2E_NODE_REPO / E2E_PYTHON_CLEAN_REPO / E2E_NODE_CLEAN_REPO)`);
  const found = await pool.query("SELECT id FROM projects WHERE user_id=$1 AND name=$2 AND repo_url=$3 ORDER BY id DESC LIMIT 1", [auth.userId, app.name, app.repo]);
  if (found.rows.length) return found.rows[0].id;
  const r = await axios.post(`${API}/api/projects`, { name: app.name, repoUrl: app.repo, githubToken: process.env.E2E_GITHUB_TOKEN }, { headers: { Authorization: `Bearer ${auth.token}` } });
  return r.data.project.id;
}

// Same request GitHub sends: signed push payload to /api/webhooks/github.
async function triggerLikeWebhook(projectId) {
  const p = (await pool.query("SELECT repo_url, webhook_secret FROM projects WHERE id=$1", [projectId])).rows[0];
  const fullName = new URL(p.repo_url).pathname.replace(/^\/|\/$|\.git$/g, "");
  const body = JSON.stringify({ ref: "refs/heads/main", after: "0".repeat(40), repository: { full_name: fullName, html_url: p.repo_url } });
  const sig = "sha256=" + crypto.createHmac("sha256", p.webhook_secret).update(body).digest("hex");
  const r = await axios.post(`${API}/api/webhooks/github`, body, {
    headers: { "Content-Type": "application/json", "X-GitHub-Event": "push", "X-Hub-Signature-256": sig, "X-GitHub-Delivery": crypto.randomUUID() },
    validateStatus: () => true,
  });
  if (r.status !== 202) fail(`webhook trigger for project ${projectId} returned ${r.status}: ${JSON.stringify(r.data)}`);
  return r.data.executionId;
}

async function waitFor(executionId) {
  const deadline = Date.now() + Number(process.env.E2E_TIMEOUT_MIN || 45) * 60000;
  let last = "";
  while (Date.now() < deadline) {
    const e = (await pool.query("SELECT * FROM pipeline_executions WHERE id=$1", [executionId])).rows[0];
    const now = `${e.status} [${e.stages_completed || ""}]`;
    if (now !== last) { console.log(`  execution ${executionId}: ${now}`); last = now; }
    if (DONE.includes(e.status)) return e;
    await sleep(10000);
  }
  fail(`execution ${executionId} did not finish in time`);
}

async function stages(executionId) {
  const one = async (sql) => (await pool.query(sql, [executionId])).rows[0];
  const sast = await one("SELECT status, started_at s, completed_at c, critical, high, medium, low, total_issues total FROM scan_history WHERE pipeline_execution_id=$1 ORDER BY id DESC LIMIT 1");
  const dep = await one("SELECT status, started_at s, completed_at c, critical, high, medium, low, total_packages pkgs FROM dependency_scans WHERE pipeline_execution_id=$1 ORDER BY id DESC LIMIT 1");
  const iac = await one("SELECT status, started_at s, completed_at c, critical, high, medium, low, total_findings total FROM iac_scans WHERE pipeline_execution_id=$1 ORDER BY id DESC LIMIT 1");
  const img = await one("SELECT status, started_at s, completed_at c, critical, high, medium, low, total_vulnerabilities total FROM image_scans WHERE pipeline_execution_id=$1 ORDER BY id DESC LIMIT 1");
  const dep2 = await one("SELECT status, deployed_at c, staging_url, failure_reason FROM deployment_history WHERE pipeline_execution_id=$1 ORDER BY id DESC LIMIT 1");
  const dast = await one("SELECT status, started_at s, completed_at c, high, medium, low, informational info, total_findings total FROM dast_scans WHERE pipeline_execution_id=$1 ORDER BY id DESC LIMIT 1");
  const sev = (r) => (r ? `C${r.critical ?? "-"} H${r.high ?? "-"} M${r.medium ?? "-"} L${r.low ?? "-"}` : "");
  return [
    ["SAST", sast, sev(sast) + (sast ? ` total=${sast.total}` : "")],
    ["Dependency", dep, sev(dep) + (dep ? ` pkgs=${dep.pkgs}` : "")],
    ["IaC", iac, sev(iac) + (iac ? ` total=${iac.total}` : "")],
    ["Image", img, sev(img) + (img ? ` total=${img.total}` : "")],
    ["Deploy", dep2, dep2 ? (dep2.failure_reason || "") : ""],
    ["DAST", dast, dast ? `H${dast.high} M${dast.medium} L${dast.low} I${dast.info} total=${dast.total}` : ""],
  ].map(([name, r, counts]) => ({ name, status: r ? r.status : "NOT_RUN", seconds: r ? secs(r.s, r.c) : "-", counts, url: r?.staging_url }));
}

// Per-finding detail: what SAST reported and what DAST found per endpoint, plus DAST crawl coverage.
async function details(executionId) {
  const sast = await pool.query(`SELECT sr.severity, sr.rule, sr.file_path, sr.line_number, sr.issue_type FROM scan_results sr
    JOIN scan_history sh ON sh.id = sr.scan_history_id WHERE sh.pipeline_execution_id=$1
      AND sh.id = (SELECT MAX(id) FROM scan_history WHERE pipeline_execution_id=$1) ORDER BY sr.file_path, sr.line_number`, [executionId]);
  for (const f of sast.rows) console.log(`  SAST  ${f.severity.padEnd(8)} ${f.issue_type || "-"} ${f.rule} ${f.file_path}:${f.line_number}`);
  const scan = (await pool.query("SELECT id, tool_provenance FROM dast_scans WHERE pipeline_execution_id=$1 ORDER BY id DESC LIMIT 1", [executionId])).rows[0];
  if (!scan) return;
  const prov = scan.tool_provenance || {};
  console.log(`  DAST  coverage ${JSON.stringify(prov.coverage || null)} seeds=${JSON.stringify(prov.seedPaths || [])} openapi=${prov.openapiUrl || "-"}`);
  const rows = await pool.query("SELECT severity, method, endpoint, param, cwe_id, alert FROM dast_findings WHERE scan_id=$1 ORDER BY endpoint, param", [scan.id]);
  for (const f of rows.rows) console.log(`  DAST  ${f.severity.padEnd(8)} CWE-${f.cwe_id} ${f.method} ${f.endpoint} param=${f.param} (${f.alert})`);
}

(async () => {
  const which = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(APPS);
  const auth = await login();
  let exit = 0;
  for (const key of which) {
    const app = APPS[key] || fail(`unknown app ${key}`);
    const projectId = await ensureProject(auth, app);
    console.log(`${app.name}: project ${projectId}, triggering pipeline`);
    const executionId = await triggerLikeWebhook(projectId);
    const e = await waitFor(executionId);
    const rows = await stages(executionId);
    console.log(`\n== ${app.name} (project ${projectId}, execution ${executionId}) ${e.status} in ${secs(e.started_at, e.completed_at)}s`);
    for (const r of rows) console.log(`${r.name.padEnd(10)} ${String(r.status).padEnd(14)} ${String(r.seconds).padStart(5)}s  ${r.counts}`);
    const staging = rows.find((r) => r.name === "Deploy").url || "-";
    console.log(`Gate: ${e.status === "COMPLETED" ? "PASSED" : "BLOCKED"}${e.failure_reason ? " — " + e.failure_reason : ""}`);
    console.log(`Staging URL: ${staging}`);
    await details(executionId);
    if (e.status !== "COMPLETED" && e.status !== "STAGE_FAILED") exit = 1;
  }
  await pool.end();
  process.exit(exit);
})().catch(async (err) => {
  console.error("e2e: " + (err.response ? `${err.config?.url} -> ${err.response.status} ${JSON.stringify(err.response.data)}` : err.stack));
  await pool.end().catch(() => {});
  process.exit(2);
});
