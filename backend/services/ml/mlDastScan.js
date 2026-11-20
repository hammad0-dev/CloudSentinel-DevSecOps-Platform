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

const MAX_SEEDS = 50;
const seedError = (message) => Object.assign(new Error(`ML DAST seed configuration: ${message}`), { status: 400, code: "ML_DAST_SEED_INVALID" });

// Crawl seeds for apps whose endpoints are not linked from HTML.
//   ML_DAST_SEED_PATHS   comma-separated paths on the staging target, e.g. "/users?id=1,/search?q=x"
//   ML_DAST_OPENAPI_URL  path (or same-origin URL) of an OpenAPI/Swagger JSON document, e.g. "/openapi.json"
// Seeds are resolved against the verified staging target and must stay on its origin; ml-dast
// enforces the same rule again under its own allowlist. (Projects have no per-project scan
// settings field, so seeds are configured for the backend instance.)
function seedConfig(target, { seedPaths = process.env.ML_DAST_SEED_PATHS, openapiUrl = process.env.ML_DAST_OPENAPI_URL } = {}) {
  const origin = new URL(target).origin;
  const list = Array.isArray(seedPaths) ? seedPaths : String(seedPaths || "").split(",");
  const paths = [...new Set(list.map((s) => String(s).trim()).filter(Boolean))];
  if (paths.length > MAX_SEEDS) throw seedError(`at most ${MAX_SEEDS} seed paths`);
  for (const p of paths) {
    if (!p.startsWith("/") || p.startsWith("//") || p.length > 500) throw seedError(`seed path "${p.slice(0, 80)}" must be a path starting with a single "/" (max 500 characters)`);
  }
  let spec = String(openapiUrl || "").trim() || null;
  if (spec) {
    let resolved;
    try { resolved = new URL(spec, target); } catch { throw seedError("ML_DAST_OPENAPI_URL is not a valid path or URL"); }
    if (resolved.origin !== origin || spec.startsWith("//")) throw seedError(`ML_DAST_OPENAPI_URL must be on the staging target ${origin}`);
    spec = resolved.href;
  }
  return { seedPaths: paths, openapiUrl: spec };
}

async function runMlBaselineScan({ pool, projectId, executionId = null, targetUrl, userId = null, client, seeds,
  maxPages = positiveInt(process.env.ML_DAST_MAX_PAGES, 50), maxRequests = positiveInt(process.env.ML_DAST_MAX_REQUESTS, 500) }) {
  const { target, authorization } = await authorizeTarget(pool, { projectId, executionId, targetUrl, userId });
  const { seedPaths, openapiUrl } = seedConfig(target, seeds); // invalid seeds fail before a scan row exists
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
    const record = engines.toolProvenance(info, { service: ml.url, maxPages, maxRequests, ...(seedPaths.length ? { seedPaths } : {}), ...(openapiUrl ? { openapiUrl } : {}) });
    await pool.query("UPDATE dast_scans SET policy_name=$1, policy_version=$2, tool_provenance=$3 WHERE id=$4 AND project_id=$5 AND status='RUNNING'", [info.name, info.version, JSON.stringify(record), scanId, projectId]);
    const args = { baseUrl: target, maxPages, maxRequests, seedPaths, openapiUrl };
    const { findings: raw, coverage } = ml.scanDetailed ? await ml.scanDetailed(args) : { findings: await ml.scan(args), coverage: null };
    if (coverage) {
      // Recorded so an empty result can be told apart from "nothing was tested" (points_found 0).
      await pool.query("UPDATE dast_scans SET tool_provenance = COALESCE(tool_provenance, '{}'::jsonb) || $1::jsonb WHERE id=$2 AND project_id=$3 AND status='RUNNING'", [JSON.stringify({ coverage }), scanId, projectId]);
    }
    const findings = dedupe(raw);
    const summary = summarize(findings);
    await persistCompletedScan(pool, scanId, projectId, findings, summary);
    return { scanId, summary, total: summary.total, scanMode: "BASELINE", engine: "ml", tool: record.tool, model: record.model, coverage };
  } catch (error) {
    await pool.query("UPDATE dast_scans SET status='FAILED', failure_reason=$1, completed_at=NOW() WHERE id=$2 AND project_id=$3 AND status='RUNNING'", [String(error.message || "ML DAST scan failed").slice(0, 2000), scanId, projectId]).catch(() => {});
    throw error;
  }
}

module.exports = { runMlBaselineScan, dedupe, seedConfig };
