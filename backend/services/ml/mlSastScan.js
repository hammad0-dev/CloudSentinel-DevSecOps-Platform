"use strict";
// SAST_ENGINE=ml: send Python/Node sources from the checkout to ml-sast and persist the findings into
// scan_history/scan_results through the same persistSastEvidence path the SonarQube engine uses.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { MlServiceError, positiveInt } = require("./mlHttp");
const { createMlSastClient } = require("./mlSastClient");
const engines = require("./engines");
const { persistSastEvidence } = require("../sastEvidence");

const SOURCE_EXTENSIONS = new Set([".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "venv", ".venv", "env", "__pycache__", "dist", "build", "coverage",
  ".next", ".nuxt", "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "bower_components"]);

function limitsFromEnv(env = process.env) {
  return {
    maxFiles: positiveInt(env.ML_SAST_MAX_FILES, 5000),
    maxFileBytes: positiveInt(env.ML_SAST_MAX_FILE_BYTES, 512 * 1024),
    maxTotalBytes: positiveInt(env.ML_SAST_MAX_TOTAL_BYTES, 20 * 1024 * 1024),
  };
}

function collectSourceFiles(root, limits = limitsFromEnv()) {
  const files = [];
  const skipped = [];
  let total = 0;
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) { if (!SKIP_DIRS.has(entry.name)) walk(abs); continue; }
      if (!entry.isFile() || !SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
      const rel = path.relative(root, abs).split(path.sep).join("/");
      const size = fs.statSync(abs).size;
      if (size > limits.maxFileBytes) { skipped.push({ path: rel, reason: "too_large" }); continue; }
      const content = fs.readFileSync(abs, "utf8");
      if (content.includes("\u0000")) { skipped.push({ path: rel, reason: "binary" }); continue; }
      total += size;
      files.push({ path: rel, content });
      if (files.length > limits.maxFiles || total > limits.maxTotalBytes) {
        throw new MlServiceError(`Repository exceeds the ML SAST input limit (${limits.maxFiles} files / ${limits.maxTotalBytes} bytes); raise ML_SAST_MAX_FILES or ML_SAST_MAX_TOTAL_BYTES.`, { code: "ML_SAST_INPUT_TOO_LARGE", status: 413 });
      }
    }
  };
  walk(root);
  return { files, skipped };
}

// ML findings -> the issue shape persistSastEvidence/coerceIssueRow/classify already accept.
// The CWE is carried in the rule ("ml:<rule>:CWE-89") because governance derives SAST references
// from the rule text; scan_results has no CWE column.
function toIssues(findings) {
  const seen = new Set();
  const issues = [];
  for (const f of findings) {
    const cwe = f.cwe_id && !/CWE-\d+/i.test(f.rule) ? `:CWE-${f.cwe_id}` : "";
    const issue = { rule: `ml:${f.rule}${cwe}`.slice(0, 512), severity: f.severity, message: f.message, component: f.file_path, line: f.line_number, type: "VULNERABILITY", confidence: f.confidence };
    const key = JSON.stringify([issue.rule, issue.severity, issue.message, issue.component, issue.line]);
    if (seen.has(key)) continue; // persistence verifies distinct rows; identical model outputs collapse
    seen.add(key);
    issues.push(issue);
  }
  return issues;
}

function inputDigest(files) {
  const h = crypto.createHash("sha256");
  for (const f of files) h.update(f.path).update("\0").update(crypto.createHash("sha256").update(f.content).digest("hex")).update("\n");
  return h.digest("hex");
}

async function runMlSast({ pool, projectId, scanHistoryId, cloneTarget, provenance, coerceIssueRow, client, limits }) {
  engines.rejectProvenanceBound(provenance?.artifact, "ML SAST");
  const ml = client || createMlSastClient();
  const info = engines.requireUsableModel(await ml.modelInfo(), "ML SAST");
  const { files, skipped } = collectSourceFiles(cloneTarget, limits || limitsFromEnv());
  if (!files.length) {
    throw new MlServiceError("No Python or Node.js source files found to scan (ML SAST reads .py .js .mjs .cjs .jsx .ts .tsx).", { code: "ML_SAST_NO_SOURCES", status: 422 });
  }
  const record = engines.toolProvenance(info, { service: ml.url, files: files.length, skippedFiles: skipped.length, inputSha256: inputDigest(files) });
  try {
    const updated = await pool.query("UPDATE scan_history SET scan_engine='ml', tool_provenance=$1 WHERE id=$2 AND project_id=$3 AND status='RUNNING' RETURNING id", [JSON.stringify(record), scanHistoryId, projectId]);
    if (updated.rows.length !== 1) throw new Error("SAST scan row is not RUNNING; refusing to record ML provenance");
  } catch (error) { throw engines.missingColumn(error); }
  const findings = await ml.scan(files);
  const issues = toIssues(findings);
  const summary = await persistSastEvidence(pool, { projectId, scanHistoryId, issues, coerceIssueRow });
  return { summary, engine: "ml", tool: record.tool, model: record.model, files: files.length, skippedFiles: skipped.length };
}

module.exports = { runMlSast, collectSourceFiles, toIssues, limitsFromEnv, SOURCE_EXTENSIONS };
