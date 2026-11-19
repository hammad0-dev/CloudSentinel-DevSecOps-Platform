// Module 11 FE-3/FE-5: alert workflow, live stream, log search and incident context.
const express = require("express");
const pool = require("../db");
const auth = require("../middleware/auth");
const alerts = require("../services/alertStore");
const loki = require("../services/lokiQuery");

const CONTEXT_MS = 5 * 60 * 1000;
const RULE_EVENTS = { failed_login_burst: "auth_login_failed", webhook_signature_burst: "webhook_signature_invalid" };

function isAdmin(user) {
  const admins = String(process.env.MONITORING_ADMIN_EMAILS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  return !!user?.email && admins.includes(String(user.email).toLowerCase());
}

// null = all alerts/logs (platform admin); otherwise the caller's own project ids.
async function projectScope(db, user) {
  if (isAdmin(user)) return null;
  const res = await db.query("SELECT id FROM projects WHERE user_id = $1", [user.id]);
  return res.rows.map((r) => r.id);
}

function sendError(res, err) {
  const status = err.status && err.status < 600 ? err.status : 500;
  return res.status(status).json({ error: status === 500 ? "Monitoring request failed" : err.message });
}

function contextQuery(alert, scope) {
  const d = alert.details || {};
  if (alert.project_id && (!scope || scope.includes(alert.project_id))) {
    if (alert.source === "k8s" && d.namespace) return { source: "k8s", labels: { namespace: d.namespace, pod: d.pod } };
    return { source: "backend", projectIds: [alert.project_id] };
  }
  if (scope) return null; // non-admins only see project-linked logs
  if (alert.source === "k8s") return { source: "k8s", labels: { namespace: d.namespace, pod: d.pod } };
  if (alert.source === "kyverno") return { source: "kyverno" };
  return { source: "backend", q: RULE_EVENTS[alert.rule] };
}

function create({ db = pool, logs = loki.queryLogs, bus = alerts.alertBus } = {}) {
  const router = express.Router();
  router.use(auth);

  router.get("/alerts", async (req, res) => {
    try {
      const { status, severity, source, projectId, from, to, limit } = req.query;
      const rows = await alerts.listAlerts(db, { status, severity, source, projectId, from, to, limit, projectScope: await projectScope(db, req.user) });
      res.json({ alerts: rows });
    } catch (err) { sendError(res, err); }
  });

  router.patch("/alerts/:id", async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid alert id" });
      const alert = await alerts.transitionAlert(db, id,
        { status: String(req.body?.status || "").toUpperCase(), note: req.body?.note, actor: req.user.email || `user:${req.user.id}` },
        { projectScope: await projectScope(db, req.user) });
      res.json({ alert });
    } catch (err) { sendError(res, err); }
  });

  router.get("/alerts/:id/context", async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid alert id" });
      const scope = await projectScope(db, req.user);
      const alert = await alerts.getAlert(db, id, { projectScope: scope });
      const created = new Date(alert.created_at).getTime();
      const first = Date.parse(alert.details?.firstSeen) || created;
      const range = { from: Math.max(Math.min(first, created) - CONTEXT_MS, created - loki.MAX_RANGE_MS + CONTEXT_MS), to: created + CONTEXT_MS, limit: 200 };

      let logResult = { lines: [], query: null, error: null };
      const q = contextQuery(alert, scope);
      if (q) {
        try {
          const r = await logs({ ...q, from: String(range.from), to: String(range.to), limit: range.limit });
          logResult = { lines: r.lines, query: r.query, error: null };
        } catch (err) { logResult.error = err.status === 503 ? err.message : "Log backend unavailable"; }
      }

      let execution = null;
      const execId = Number(alert.details?.pipelineExecutionId);
      if (Number.isInteger(execId) && execId > 0) {
        execution = (await db.query("SELECT * FROM pipeline_executions WHERE id = $1 AND project_id IS NOT DISTINCT FROM $2", [execId, alert.project_id])).rows[0] || null;
      } else if (alert.project_id) {
        execution = (await db.query(
          "SELECT * FROM pipeline_executions WHERE project_id = $1 AND started_at <= $2 ORDER BY started_at DESC LIMIT 1",
          [alert.project_id, new Date(range.to).toISOString()])).rows[0] || null;
      }
      res.json({ alert, window: { from: new Date(range.from).toISOString(), to: new Date(range.to).toISOString() }, logs: logResult, execution });
    } catch (err) { sendError(res, err); }
  });

  router.get("/logs", async (req, res) => {
    try {
      const scope = await projectScope(db, req.user);
      const { q, from, to, limit } = req.query;
      let source = req.query.source || undefined;
      if (scope && !source) source = "backend";
      const result = await logs({ source, q, from, to, limit, projectIds: scope });
      res.json(result);
    } catch (err) {
      if (err.status === 400 || err.status === 503) return res.status(err.status).json({ error: err.message });
      res.status(502).json({ error: "Log backend unavailable" });
    }
  });

  // SSE; the client reads it with fetch() so the JWT stays in the Authorization header.
  router.get("/stream", async (req, res) => {
    let scope;
    try { scope = await projectScope(db, req.user); } catch (err) { return sendError(res, err); }
    res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.flushHeaders?.();
    res.write("retry: 5000\n\n");
    const onAlert = ({ type, alert }) => {
      if (scope && !scope.includes(alert.project_id)) return;
      res.write(`event: alert\ndata: ${JSON.stringify({ type, alert })}\n\n`);
    };
    bus.on("alert", onAlert);
    const ping = setInterval(() => res.write(": ping\n\n"), 25000);
    req.on("close", () => { clearInterval(ping); bus.off("alert", onAlert); });
  });

  return router;
}

module.exports = create();
module.exports.create = create;
module.exports.isAdmin = isAdmin;
