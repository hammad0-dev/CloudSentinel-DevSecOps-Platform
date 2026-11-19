// Module 11 FE-3/FE-5: security_alerts persistence and status workflow.
const { EventEmitter } = require("events");

const STATUSES = ["OPEN", "ACKNOWLEDGED", "RESOLVED"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SOURCES = ["backend", "k8s", "kyverno"];
const TRANSITIONS = { OPEN: ["ACKNOWLEDGED", "RESOLVED"], ACKNOWLEDGED: ["RESOLVED"], RESOLVED: [] };
const alertBus = new EventEmitter();
alertBus.setMaxListeners(200);

function canTransition(from, to) {
  return (TRANSITIONS[from] || []).includes(to);
}

function fromStatesFor(to) {
  return STATUSES.filter((s) => canTransition(s, to));
}

class AlertError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function createAlert(db, detection, { cooldownMs = 10 * 60 * 1000 } = {}) {
  const key = detection.details?.key;
  if (!key) throw new Error("detection.details.key is required");
  const cooldown = Math.max(cooldownMs, Number(detection.details?.windowMs) || 0);
  const res = await db.query(
    `INSERT INTO security_alerts (rule, severity, source, project_id, details)
     SELECT $1, $2, $3, (SELECT id FROM projects WHERE id = $4), $5::jsonb
     WHERE NOT EXISTS (
       SELECT 1 FROM security_alerts
       WHERE rule = $1 AND details->>'key' = $6 AND resolved_at > NOW() - ($7::bigint * INTERVAL '1 millisecond'))
     ON CONFLICT (rule, (details->>'key')) WHERE status <> 'RESOLVED' DO NOTHING
     RETURNING *`,
    [detection.rule, detection.severity, detection.source, Number.isInteger(detection.projectId) ? detection.projectId : null,
      JSON.stringify(detection.details), key, cooldown]
  );
  const alert = res.rows[0] || null;
  if (alert) alertBus.emit("alert", { type: "created", alert });
  return alert;
}

function buildListQuery({ status, severity, source, projectId, from, to, limit, projectScope } = {}) {
  const where = [];
  const params = [];
  const add = (sql, value) => { params.push(value); where.push(sql.replace("?", `$${params.length}`)); };
  const list = (v, allowed) => String(v).split(",").map((s) => s.trim().toUpperCase()).filter((s) => allowed.includes(s));
  if (status) { const v = list(status, STATUSES); if (!v.length) throw new AlertError(400, "Invalid status filter"); add("status = ANY(?::text[])", v); }
  if (severity) { const v = list(severity, SEVERITIES); if (!v.length) throw new AlertError(400, "Invalid severity filter"); add("severity = ANY(?::text[])", v); }
  if (source) { if (!SOURCES.includes(source)) throw new AlertError(400, "Invalid source filter"); add("source = ?", source); }
  if (projectId !== undefined && projectId !== "") {
    const p = Number(projectId);
    if (!Number.isInteger(p)) throw new AlertError(400, "Invalid projectId");
    add("project_id = ?", p);
  }
  for (const [value, op] of [[from, ">="], [to, "<="]]) {
    if (!value) continue;
    const t = Date.parse(value);
    if (!Number.isFinite(t)) throw new AlertError(400, "Invalid time filter");
    add(`created_at ${op} ?`, new Date(t).toISOString());
  }
  if (projectScope) add("project_id = ANY(?::int[])", projectScope);
  const n = Math.min(Math.max(Number.parseInt(limit, 10) || 100, 1), 500);
  params.push(n);
  return {
    text: `SELECT * FROM security_alerts${where.length ? " WHERE " + where.join(" AND ") : ""} ORDER BY created_at DESC, id DESC LIMIT $${params.length}`,
    params,
  };
}

async function listAlerts(db, filters) {
  const q = buildListQuery(filters);
  return (await db.query(q.text, q.params)).rows;
}

async function getAlert(db, id, { projectScope } = {}) {
  const res = await db.query("SELECT * FROM security_alerts WHERE id = $1", [id]);
  const alert = res.rows[0];
  if (!alert || (projectScope && !projectScope.includes(alert.project_id))) throw new AlertError(404, "Alert not found");
  return alert;
}

async function transitionAlert(db, id, { status, note, actor } = {}, { projectScope } = {}) {
  if (!STATUSES.includes(status) || status === "OPEN") throw new AlertError(400, "status must be ACKNOWLEDGED or RESOLVED");
  if (note !== undefined && note !== null && (typeof note !== "string" || note.length > 2000)) throw new AlertError(400, "note must be a string up to 2000 chars");
  const current = await getAlert(db, id, { projectScope });
  if (!canTransition(current.status, status)) throw new AlertError(409, `Cannot move alert from ${current.status} to ${status}`);
  const entry = note && note.trim() ? `[${new Date().toISOString()} ${status}${actor ? " by " + actor : ""}] ${note.trim()}` : null;
  const res = await db.query(
    `UPDATE security_alerts
        SET status = $2,
            note = CASE WHEN $3::text IS NULL THEN note ELSE concat_ws(E'\\n', note, $3::text) END,
            resolved_at = CASE WHEN $2 = 'RESOLVED' THEN NOW() ELSE resolved_at END
      WHERE id = $1 AND status = ANY($4::text[])
      RETURNING *`,
    [id, status, entry, fromStatesFor(status)]
  );
  if (!res.rows[0]) throw new AlertError(409, "Alert status changed concurrently");
  alertBus.emit("alert", { type: "updated", alert: res.rows[0] });
  return res.rows[0];
}

module.exports = {
  STATUSES, SEVERITIES, SOURCES, TRANSITIONS, AlertError, alertBus,
  canTransition, createAlert, buildListQuery, listAlerts, getAlert, transitionAlert,
};
