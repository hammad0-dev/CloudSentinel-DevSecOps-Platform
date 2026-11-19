// Module 11 FE-3: Prometheus metrics (prom-client) exposed at GET /metrics.
const client = require("prom-client");

const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry, prefix: "cloudsentinel_" });
let db = null;

const pipelineRuns = new client.Counter({
  name: "cloudsentinel_pipeline_runs_total",
  help: "Pipeline runs by final status (started, completed, failed, other)",
  labelNames: ["status"],
  registers: [registry],
});

const stageDuration = new client.Histogram({
  name: "cloudsentinel_pipeline_stage_duration_seconds",
  help: "Pipeline stage duration by stage and outcome",
  labelNames: ["stage", "outcome"],
  buckets: [5, 15, 30, 60, 120, 300, 600, 1200, 1800],
  registers: [registry],
});

// Latest COMPLETED scan per project and scanner.
const FINDING_QUERIES = {
  SAST: "SELECT DISTINCT ON (project_id) critical, high, medium, low FROM scan_history WHERE scan_type = 'SAST' AND status = 'COMPLETED' ORDER BY project_id, id DESC",
  DEPENDENCY: "SELECT DISTINCT ON (project_id) critical, high, medium, low FROM dependency_scans WHERE status = 'COMPLETED' ORDER BY project_id, id DESC",
  IAC: "SELECT DISTINCT ON (project_id) critical, high, medium, low FROM iac_scans WHERE status = 'COMPLETED' ORDER BY project_id, id DESC",
  DAST: "SELECT DISTINCT ON (project_id) 0 AS critical, high, medium, low FROM dast_scans WHERE status = 'COMPLETED' ORDER BY project_id, id DESC",
};

new client.Gauge({
  name: "cloudsentinel_findings",
  help: "Findings by scanner and severity across each project's latest completed scan",
  labelNames: ["source", "severity"],
  registers: [registry],
  async collect() {
    this.reset();
    if (!db) return;
    for (const [source, sql] of Object.entries(FINDING_QUERIES)) {
      try {
        const totals = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const row of (await db.query(sql)).rows) for (const k of Object.keys(totals)) totals[k] += Number(row[k] || 0);
        for (const [severity, value] of Object.entries(totals)) this.set({ source, severity: severity.toUpperCase() }, value);
      } catch { /* table/column missing on this install: skip source */ }
    }
  },
});

new client.Gauge({
  name: "cloudsentinel_open_alerts",
  help: "Security alerts not yet RESOLVED, by severity",
  labelNames: ["severity"],
  registers: [registry],
  async collect() {
    this.reset();
    if (!db) return;
    try {
      const res = await db.query("SELECT severity, COUNT(*)::int AS n FROM security_alerts WHERE status <> 'RESOLVED' GROUP BY severity");
      for (const row of res.rows) this.set({ severity: row.severity }, row.n);
    } catch { /* migration 021 not applied */ }
  },
});

function init(pool) { db = pool; }

// Optional bearer token (METRICS_TOKEN) so the endpoint is not public when exposed beyond the cluster.
async function handler(req, res) {
  const token = process.env.METRICS_TOKEN;
  if (token && req.headers.authorization !== `Bearer ${token}`) return res.status(401).end();
  res.set("Content-Type", registry.contentType);
  res.end(await registry.metrics());
}

module.exports = { registry, pipelineRuns, stageDuration, init, handler };
