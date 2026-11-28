// Module 11 (FE-1..FE-5) unit tests: node --test test/monitoring.test.js
process.env.APP_LOG_FILE = "off";
process.env.APP_LOG_STDOUT = "off";
const test = require("node:test");
const assert = require("node:assert/strict");
const { evaluateRules, RULES, collectK8sSignals, start } = require("../services/threatDetection");
const alerts = require("../services/alertStore");
const { buildLogQL, buildRange, queryLogs, LogQueryError } = require("../services/lokiQuery");
const securityLog = require("../services/securityLog");
const telemetry = require("../services/pipelineTelemetry");

const NOW = Date.parse("2026-11-19T12:00:00Z");
const ago = (ms) => new Date(NOW - ms).toISOString();
const ev = (event, extra = {}) => ({ ts: ago(extra.ago ?? 1000), level: "warn", source: "backend", event, projectId: null, userId: null, ip: "10.0.0.1", detail: {}, ...extra });
const rule = (name) => RULES.find((r) => r.name === name);
const only = (name, input) => evaluateRules({ now: NOW, rules: [rule(name)], ...input });

// ---- FE-2 detection rules ----
test("every rule has name, severity, threshold, window", () => {
  for (const r of RULES) {
    assert.ok(r.name && ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(r.severity));
    assert.ok(Number.isInteger(r.threshold) && r.threshold > 0);
    assert.ok(["backend", "k8s", "kyverno"].includes(r.source));
  }
});

test("failed_login_burst: 5 failures for one account triggers, 4 does not", () => {
  const fails = (n, account, ipBase) => Array.from({ length: n }, (_, i) => ev("auth_login_failed", { ip: `${ipBase}.${i}`, detail: { account } }));
  assert.equal(only("failed_login_burst", { events: fails(4, "a@x.io", "10.1") }).length, 0);
  const hits = only("failed_login_burst", { events: fails(5, "a@x.io", "10.1") });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].details.key, "account:a@x.io");
  assert.equal(hits[0].severity, "HIGH");
});

test("failed_login_burst: 5 failures from one IP across accounts triggers by ip", () => {
  const events = ["a", "b", "c", "d", "e"].map((a) => ev("auth_login_failed", { ip: "203.0.113.9", detail: { account: a } }));
  const hits = only("failed_login_burst", { events });
  assert.deepEqual(hits.map((h) => h.details.key), ["ip:203.0.113.9"]);
});

test("failed_login_burst: failures older than 5 minutes are ignored", () => {
  const events = Array.from({ length: 6 }, (_, i) => ev("auth_login_failed", { ago: (i < 2 ? 1 : 6) * 60000, detail: { account: "a" } }));
  assert.equal(only("failed_login_burst", { events }).length, 0);
});

test("webhook_signature_burst: 3 in 5 min triggers, 2 does not", () => {
  const sig = (n) => Array.from({ length: n }, () => ev("webhook_signature_invalid", { detail: { repository: "o/r" } }));
  assert.equal(only("webhook_signature_burst", { events: sig(2) }).length, 0);
  const [hit] = only("webhook_signature_burst", { events: sig(3) });
  assert.equal(hit.details.count, 3);
  assert.deepEqual(hit.details.repositories, ["o/r"]);
  assert.equal(only("webhook_signature_burst", { events: [...sig(2), ev("webhook_signature_invalid", { ago: 6 * 60000 })] }).length, 0);
});

test("pipeline_trigger_anomaly: >5 runs in 10 min for one project", () => {
  const runs = (n, projectId) => Array.from({ length: n }, (_, i) => ev("pipeline_started", { projectId, detail: { executionId: 100 + i } }));
  assert.equal(only("pipeline_trigger_anomaly", { events: [...runs(5, 7), ...runs(5, 8)] }).length, 0);
  const [hit] = only("pipeline_trigger_anomaly", { events: runs(6, 7) });
  assert.equal(hit.projectId, 7);
  assert.equal(hit.details.pipelineExecutionId, 105);
});

const pod = (ns, restarts, waiting, finishedAgo) => ({
  metadata: { namespace: ns, name: "web-1" },
  status: { containerStatuses: [{ name: "app", restartCount: restarts, state: waiting ? { waiting: { reason: waiting } } : { running: {} },
    lastState: finishedAgo === undefined ? {} : { terminated: { finishedAt: ago(finishedAgo) } } }] },
});

test("k8s_pod_restart_loop: CrashLoopBackOff or recent restarts >=5 in project namespace", () => {
  assert.equal(only("k8s_pod_restart_loop", { k8s: { pods: [pod("cloudsentinel-p-3", 4, null, 1000)] } }).length, 0);
  assert.equal(only("k8s_pod_restart_loop", { k8s: { pods: [pod("cloudsentinel-p-3", 9, null, 60 * 60000)] } }).length, 0, "old restarts are not a loop");
  assert.equal(only("k8s_pod_restart_loop", { k8s: { pods: [pod("kube-system", 9, "CrashLoopBackOff")] } }).length, 0, "namespace filter");
  const [hit] = only("k8s_pod_restart_loop", { k8s: { pods: [pod("cloudsentinel-p-3", 2, "CrashLoopBackOff")] } });
  assert.equal(hit.projectId, 3);
  assert.equal(hit.details.key, "cloudsentinel-p-3/web-1/app");
  assert.equal(only("k8s_pod_restart_loop", { k8s: { pods: [pod("cloudsentinel-p-3", 5, null, 60000)] } }).length, 1);
});

test("kyverno_denied_spike: >=5 policy violations in one namespace in 5 min", () => {
  const e = (ns, count, agoMs = 1000) => ({ reason: "PolicyViolation", count, lastTimestamp: ago(agoMs), involvedObject: { namespace: ns, name: "disallow-privileged" }, message: "blocked" });
  assert.equal(only("kyverno_denied_spike", { k8s: { kyvernoEvents: [e("cloudsentinel-p-2", 4)] } }).length, 0);
  assert.equal(only("kyverno_denied_spike", { k8s: { kyvernoEvents: [e("cloudsentinel-p-2", 4), e("cloudsentinel-p-2", 9, 10 * 60000)] } }).length, 0);
  const [hit] = only("kyverno_denied_spike", { k8s: { kyvernoEvents: [e("cloudsentinel-p-2", 3), e("cloudsentinel-p-2", 2)] } });
  assert.equal(hit.projectId, 2);
  assert.equal(hit.details.count, 5);
});

test("no k8s data yields no k8s detections", () => {
  assert.equal(evaluateRules({ now: NOW, events: [], k8s: null }).length, 0);
});

test("collectK8sSignals uses kubectl (mocked)", async () => {
  const calls = [];
  const run = (cmd, args, opts, cb) => { calls.push([cmd, ...args]); cb(null, JSON.stringify({ items: [{ x: 1 }] })); };
  const s = await collectK8sSignals({ run });
  assert.equal(calls.length, 2);
  assert.ok(calls.every((c) => c[0] === "kubectl"));
  assert.deepEqual(s.pods, [{ x: 1 }]);
});

test("detector tick forwards detections to createAlert", async () => {
  process.env.K8S_SIGNALS = "off";
  const created = [];
  const now = Date.now();
  const events = Array.from({ length: 3 }, () => ({ ...ev("webhook_signature_invalid"), ts: new Date(now - 1000).toISOString() }));
  const d = start({ intervalMs: 1e9, getEvents: () => events, createAlert: async (x) => created.push(x) });
  await d.tick();
  d.stop();
  delete process.env.K8S_SIGNALS;
  assert.equal(created.length, 1);
  assert.equal(created[0].rule, "webhook_signature_burst");
});

// ---- FE-1 structured events ----
test("logEvent emits one structured entry with required fields", () => {
  securityLog._reset();
  const e = securityLog.logEvent({ event: "auth_login_failed", ip: "1.2.3.4", projectId: "5", detail: { account: "a" } });
  assert.deepEqual(Object.keys(e), ["ts", "level", "source", "event", "projectId", "userId", "ip", "detail"]);
  assert.equal(e.projectId, 5);
  assert.equal(securityLog.recentEvents().length, 1);
});

test("pipeline telemetry logs stage start/finish/fail and deployment result", async () => {
  securityLog._reset();
  const ok = telemetry.instrumentStage(async () => ({ stagingUrl: "http://s" }), () => "Deploy");
  await ok(1, 2, 3);
  const bad = telemetry.instrumentStage(async () => { throw new Error("boom"); });
  await assert.rejects(bad(1, 2, 3, "SAST", "sast"));
  const names = securityLog.recentEvents().map((e) => e.event + (e.detail.status ? ":" + e.detail.status : ""));
  assert.deepEqual(names, ["pipeline_stage_started", "pipeline_stage_finished", "deployment_result:SUCCESS", "pipeline_stage_started", "pipeline_stage_failed"]);

  securityLog._reset();
  const pool = { query: async () => ({ rows: [{ status: "STAGE_FAILED", failure_reason: "x" }] }) };
  await telemetry.instrumentPipeline(async () => ({}), pool)(9, 2, 3);
  assert.deepEqual(securityLog.recentEvents().map((e) => e.event), ["pipeline_started", "pipeline_failed"]);
});

// ---- FE-3/FE-5 alert status transitions ----
function fakeDb(initial) {
  const row = { id: 1, project_id: 4, note: null, resolved_at: null, ...initial };
  return {
    row,
    async query(sql, params) {
      if (/^SELECT \* FROM security_alerts WHERE id/.test(sql)) return { rows: params[0] === row.id ? [{ ...row }] : [] };
      if (/^UPDATE security_alerts/.test(sql.trim())) {
        if (!params[3].includes(row.status)) return { rows: [] };
        row.status = params[1];
        if (params[2]) row.note = row.note ? row.note + "\n" + params[2] : params[2];
        if (params[1] === "RESOLVED") row.resolved_at = new Date();
        return { rows: [{ ...row }] };
      }
      throw new Error("unexpected sql " + sql);
    },
  };
}

test("transition table", () => {
  assert.ok(alerts.canTransition("OPEN", "ACKNOWLEDGED"));
  assert.ok(alerts.canTransition("OPEN", "RESOLVED"));
  assert.ok(alerts.canTransition("ACKNOWLEDGED", "RESOLVED"));
  assert.ok(!alerts.canTransition("ACKNOWLEDGED", "OPEN"));
  assert.ok(!alerts.canTransition("RESOLVED", "ACKNOWLEDGED"));
  assert.ok(!alerts.canTransition("RESOLVED", "OPEN"));
});

test("OPEN -> ACKNOWLEDGED -> RESOLVED with notes; RESOLVED is terminal", async () => {
  const db = fakeDb({ status: "OPEN" });
  const seen = [];
  const listener = (m) => seen.push(m.type + ":" + m.alert.status);
  alerts.alertBus.on("alert", listener);
  await alerts.transitionAlert(db, 1, { status: "ACKNOWLEDGED", note: "looking", actor: "ops@x" });
  const done = await alerts.transitionAlert(db, 1, { status: "RESOLVED", note: "blocked ip" });
  alerts.alertBus.off("alert", listener);
  assert.equal(done.status, "RESOLVED");
  assert.ok(done.resolved_at);
  assert.match(done.note, /ACKNOWLEDGED by ops@x\] looking\n.*RESOLVED\] blocked ip/);
  assert.deepEqual(seen, ["updated:ACKNOWLEDGED", "updated:RESOLVED"]);
  await assert.rejects(alerts.transitionAlert(db, 1, { status: "ACKNOWLEDGED" }), (e) => e.status === 409);
});

test("transition rejects invalid status, foreign project, unknown id", async () => {
  const db = fakeDb({ status: "OPEN" });
  await assert.rejects(alerts.transitionAlert(db, 1, { status: "OPEN" }), (e) => e.status === 400);
  await assert.rejects(alerts.transitionAlert(db, 1, { status: "BOGUS" }), (e) => e.status === 400);
  await assert.rejects(alerts.transitionAlert(db, 1, { status: "RESOLVED" }, { projectScope: [9] }), (e) => e.status === 404);
  await assert.rejects(alerts.transitionAlert(db, 2, { status: "RESOLVED" }), (e) => e.status === 404);
  assert.equal(db.row.status, "OPEN");
});

test("createAlert inserts with dedupe/cooldown and emits only when new", async () => {
  const sqls = [];
  let emitted = 0;
  const l = () => emitted++;
  alerts.alertBus.on("alert", l);
  const db = { query: async (sql, params) => { sqls.push([sql, params]); return { rows: sqls.length === 1 ? [{ id: 1 }] : [] }; } };
  const d = { rule: "r", severity: "HIGH", source: "backend", projectId: 3, details: { key: "k", windowMs: 300000 } };
  assert.ok(await alerts.createAlert(db, d));
  assert.equal(await alerts.createAlert(db, d), null);
  alerts.alertBus.off("alert", l);
  assert.equal(emitted, 1);
  assert.match(sqls[0][0], /ON CONFLICT \(rule, \(details->>'key'\)\) WHERE status <> 'RESOLVED' DO NOTHING/);
  assert.equal(sqls[0][1][6], 600000);
});

test("list filters are parameterised and validated", () => {
  const q = alerts.buildListQuery({ severity: "high,critical", status: "OPEN", projectScope: [1, 2], limit: "9999" });
  assert.match(q.text, /severity = ANY\(\$2::text\[\]\)/);
  assert.deepEqual(q.params, [["OPEN"], ["HIGH", "CRITICAL"], [1, 2], 500]);
  assert.throws(() => alerts.buildListQuery({ severity: "'; DROP TABLE x;--" }), (e) => e.status === 400);
  assert.throws(() => alerts.buildListQuery({ source: "aws" }), (e) => e.status === 400);
});

// ---- FE-5 LogQL builder ----
test("buildLogQL builds selectors and literal filters", () => {
  assert.equal(buildLogQL({}), '{source=~"backend|k8s|kyverno"}');
  assert.equal(buildLogQL({ source: "kyverno", q: "disallow-privileged" }), '{source="kyverno"} |~ "(?i)disallow-privileged"');
  assert.equal(buildLogQL({ source: "backend", q: "a.b(c)" }), '{source="backend"} |~ "(?i)a\\\\.b\\\\(c\\\\)"');
  assert.equal(buildLogQL({ source: "backend", projectIds: [1, 2] }), '{source="backend"} | json projectId="projectId" | projectId=~"1|2"');
  assert.equal(buildLogQL({ source: "k8s", projectIds: [3], labels: { namespace: "cloudsentinel-p-3" } }), '{source="k8s", namespace="cloudsentinel-p-3", project_id=~"3"}');
});

test("buildLogQL rejects injection attempts", () => {
  const bad = [
    { q: '"} or {source=~".+' },
    { q: "x\" | line_format \"{{.secret}}" },
    { q: "a | json" },
    { q: "`raw`" },
    { q: "a\\\"b" },
    { q: "x".repeat(201) },
    { q: "line\nnext" },
    { source: 'backend"}' },
    { source: "aws" },
    { labels: { namespace: 'x",source=~".*' } },
    { labels: { app: "x" } },
    { source: "backend", projectIds: ["1|.*"] },
    { source: "kyverno", projectIds: [1] },
    { source: "backend", projectIds: [] },
  ];
  for (const input of bad) assert.throws(() => buildLogQL(input), LogQueryError, JSON.stringify(input));
});

test("buildRange bounds range and limit", () => {
  const r = buildRange({ now: NOW });
  assert.equal(BigInt(r.end) - BigInt(r.start), 3600000000000n);
  assert.equal(r.limit, 200);
  assert.equal(buildRange({ limit: "50000", now: NOW }).limit, 1000);
  assert.throws(() => buildRange({ from: ago(25 * 3600000), to: ago(0) }), /24 hours/);
  assert.throws(() => buildRange({ from: ago(0), to: ago(1000) }), /before/);
  assert.throws(() => buildRange({ from: "yesterday" }), /Invalid from/);
  assert.throws(() => buildRange({ limit: "-1" }), /limit/);
});

test("queryLogs calls Loki query_range (mocked) and flattens streams", async () => {
  let call;
  const http = { get: async (url, opts) => { call = { url, opts }; return { data: { data: { result: [
    { stream: { source: "backend" }, values: [["1763553600000000000", '{"event":"auth_login_failed"}']] },
    { stream: { source: "k8s", namespace: "cloudsentinel-p-1" }, values: [["1763553660000000000", "plain"]] },
  ] } } }; } };
  const r = await queryLogs({ source: "backend", q: "auth" }, { http, baseUrl: "http://loki:3100/", now: NOW });
  assert.equal(call.url, "http://loki:3100/loki/api/v1/query_range");
  assert.equal(call.opts.params.query, '{source="backend"} |~ "(?i)auth"');
  assert.equal(call.opts.params.direction, "backward");
  assert.equal(r.lines.length, 2);
  assert.equal(r.lines[0].line, "plain");
  assert.equal(r.lines[1].parsed.event, "auth_login_failed");
  await assert.rejects(queryLogs({}, { http, baseUrl: "" }), (e) => e.status === 503);
});

// ---- FE-3/FE-5 routes (mock db + mock Loki) ----
test("monitoring routes: scoped logs, context, SSE", async () => {
  process.env.JWT_SECRET = "test-secret";
  const jwt = require("jsonwebtoken");
  const express = require("express");
  const alert = { id: 7, rule: "pipeline_trigger_anomaly", severity: "MEDIUM", source: "backend", project_id: 4, status: "OPEN",
    details: { key: "project:4", pipelineExecutionId: 55, firstSeen: new Date(Date.now() - 60000).toISOString() }, created_at: new Date() };
  const db = { query: async (sql, params) => {
    if (sql.startsWith("SELECT id FROM projects")) return { rows: [{ id: 4 }] };
    if (sql.startsWith("SELECT * FROM security_alerts WHERE id")) return { rows: params[0] === 7 ? [alert] : [] };
    if (sql.startsWith("SELECT * FROM pipeline_executions WHERE id")) return { rows: [{ id: 55, project_id: 4, status: "COMPLETED" }] };
    throw new Error(sql);
  } };
  const logCalls = [];
  const logs = async (p) => { logCalls.push(p); return { query: buildLogQL(p), lines: [{ line: "x" }] }; };
  const app = express().use(express.json()).use("/m", require("../routes/monitoring").create({ db, logs }));
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}/m`;
  const headers = { Authorization: `Bearer ${jwt.sign({ id: 1, email: "user@x.io" }, "test-secret")}` };
  try {
    assert.equal((await fetch(base + "/alerts")).status, 401);
    const l = await fetch(base + "/logs?q=deploy", { headers });
    assert.equal(l.status, 200);
    assert.deepEqual(logCalls[0], { source: "backend", q: "deploy", from: undefined, to: undefined, limit: undefined, projectIds: [4] });
    assert.equal((await fetch(base + "/logs?source=kyverno", { headers })).status, 400, "non-admin cannot read kyverno logs");
    assert.equal((await fetch(base + "/logs?q=%22%7D", { headers })).status, 400);
    // project selector: own project narrows the scope; foreign or invalid ids are refused before Loki is queried
    const before = logCalls.length;
    assert.equal((await fetch(base + "/logs?projectId=4&source=k8s", { headers })).status, 200);
    assert.deepEqual(logCalls.at(-1).projectIds, [4]); assert.equal(logCalls.at(-1).source, "k8s");
    assert.equal(buildLogQL(logCalls.at(-1)), '{source="k8s", project_id=~"4"}');
    assert.equal((await fetch(base + "/logs?projectId=99", { headers })).status, 404);
    assert.equal((await fetch(base + "/logs?projectId=abc", { headers })).status, 400);
    assert.equal(logCalls.length, before + 1);

    const c = await (await fetch(base + "/alerts/7/context", { headers })).json();
    assert.equal(c.execution.id, 55);
    assert.equal(c.logs.query, '{source="backend"} | json projectId="projectId" | projectId=~"4"');
    assert.equal(Date.parse(c.window.to) - Date.parse(c.window.from), 11 * 60000, "firstSeen-5min .. created+5min");
    assert.equal((await fetch(base + "/alerts/8/context", { headers })).status, 404);

    const ctrl = new AbortController();
    const s = await fetch(base + "/stream", { headers, signal: ctrl.signal });
    assert.match(s.headers.get("content-type"), /^text\/event-stream/);
    const reader = s.body.getReader();
    await reader.read(); // retry line
    alerts.alertBus.emit("alert", { type: "created", alert: { ...alert, project_id: 99 } }); // other tenant: filtered
    alerts.alertBus.emit("alert", { type: "created", alert });
    const chunk = new TextDecoder().decode((await reader.read()).value);
    assert.match(chunk, /^event: alert\ndata: .*"id":7/);
    ctrl.abort();
  } finally {
    server.closeAllConnections();
    server.close();
  }
});
