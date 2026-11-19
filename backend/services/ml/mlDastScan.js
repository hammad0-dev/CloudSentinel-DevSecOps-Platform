"use strict";
// DAST_ENGINE=ml on the baseline DAST path: same target authorization, dast_scans row, finding
// fingerprints and persistence as the ZAP baseline scanner; ml-dast replaces only the scanner.
const crypto = require("crypto");
const { positiveInt } = require("./mlHttp");
const { createMlDastClient } = require("./mlDastClient");
const engines = require("./engines");
const { authorizeTarget, persistCompletedScan, summarize, fingerprint } = require("../dastBaselineScanner");

function dedupe(findings) {
  const out = new Map();
  for (const f of findings) {
    const row = { ...f };
    delete row.confidence; // not a dast_findings column, not part of identity
    row.finding_fingerprint = fingerprint(row);
    if (!out.has(row.finding_fingerprint)) out.set(row.finding_fingerprint, row);
  }
  return [...out.values()];
}

async function runMlBaselineScan({ pool, projectId, executionId = null, targetUrl, userId = null, client,
  maxPages = positiveInt(process.env.ML_DAST_MAX_PAGES, 50), maxRequests = positiveInt(process.env.ML_DAST_MAX_REQUESTS, 500) }) {
  const { target, authorization } = await authorizeTarget(pool, { projectId, executionId, targetUrl, userId });
  engines.rejectProvenanceBound(await require("../stageProvenance").binding(pool, { projectId, executionId, userId }), "ML DAST");
  const active = await pool.query("SELECT id FROM dast_scans WHERE project_id=$1 AND status='RUNNING' LIMIT 1", [projectId]);
  if (active.rows.length) throw Object.assign(new Error("A DAST scan is already running for this project."), { status: 409 });
  const ml = client || createMlDastClient();
  let created;
  try {
    created = await pool.query("INSERT INTO dast_scans (project_id,pipeline_execution_id,target_url,status,started_at,scan_mode,scan_group_id,policy_name,policy_version,target_authorization,scan_engine) VALUES ($1,$2,$3,'RUNNING',NOW(),'BASELINE',$4,'ml-dast','pending',$5,'ml') RETURNING id", [projectId, executionId, target, crypto.randomUUID(), JSON.stringify(authorization)]);
  } catch (error) { throw engines.missingColumn(error); }
  const scanId = created.rows[0].id;
  try {
    const info = engines.requireUsableModel(await ml.modelInfo(), "ML DAST");
    const record = engines.toolProvenance(info, { service: ml.url, maxPages, maxRequests });
    await pool.query("UPDATE dast_scans SET policy_name=$1, policy_version=$2, tool_provenance=$3 WHERE id=$4 AND project_id=$5 AND status='RUNNING'", [info.name, info.version, JSON.stringify(record), scanId, projectId]);
    const findings = dedupe(await ml.scan({ baseUrl: target, maxPages, maxRequests }));
    const summary = summarize(findings);
    await persistCompletedScan(pool, scanId, projectId, findings, summary);
    return { scanId, summary, total: summary.total, scanMode: "BASELINE", engine: "ml", tool: record.tool, model: record.model };
  } catch (error) {
    await pool.query("UPDATE dast_scans SET status='FAILED', failure_reason=$1, completed_at=NOW() WHERE id=$2 AND project_id=$3 AND status='RUNNING'", [String(error.message || "ML DAST scan failed").slice(0, 2000), scanId, projectId]).catch(() => {});
    throw error;
  }
}

module.exports = { runMlBaselineScan, dedupe };
