"use strict";

const express = require("express");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const pool = require("../db");
const auth = require("../middleware/auth");

const router = express.Router();

const DOCKER_CMD = process.env.DOCKER_CMD || "docker";
const ZAP_IMAGE  = process.env.ZAP_IMAGE  || "zaproxy/zap-stable";

function parseEnvMs(raw, fallback) {
  const n = Number.parseInt(String(raw ?? "").trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const DAST_TIMEOUT_MS = parseEnvMs(process.env.DAST_TIMEOUT_MS, 1_800_000); // 30 min default

// ------------------------------------------------------------------ helpers

function spawnWithTimeout(label, command, args, spawnOptions, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, spawnOptions);
    let stdout = "";
    let stderr = "";
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill("SIGKILL"); } catch (_) {}
      reject(new Error(label + ": timed out after " + Math.round(timeoutMs / 1000) + "s."));
    }, timeoutMs);

    child.stdout?.on("data", (c) => { stdout += c; });
    child.stderr?.on("data", (c) => { stderr += c; });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // ZAP baseline exits 1 when alerts found, 2 when WARN-only alerts found — both are success.
      if (code === 0 || code === 1 || code === 2) resolve({ stdout, stderr, code });
      else reject(new Error((stderr || stdout || label + " exited " + code).trim()));
    });
  });
}

function parseTrivyJson(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

/**
 * Map ZAP riskcode integer to severity string.
 * ZAP: 0=Informational 1=Low 2=Medium 3=High
 */
function zapRiskToSeverity(riskcode) {
  const rc = Number(riskcode);
  if (rc === 3) return "HIGH";
  if (rc === 2) return "MEDIUM";
  if (rc === 1) return "LOW";
  return "INFORMATIONAL";
}

/**
 * Flatten ZAP JSON report (new "site" array format) into finding rows.
 * ZAP JSON structure:
 *   { "site": [{ "alerts": [{ "name", "riskcode", "confidence", "pluginid",
 *      "cweid", "solution", "desc", "instances": [{ "uri","method","param","attack","evidence" }] }] }] }
 */
function extractDastFindings(zapData) {
  const findings = [];
  const sites = zapData?.site || [];
  for (const site of sites) {
    const alerts = site?.alerts || [];
    for (const alert of alerts) {
      const severity = zapRiskToSeverity(alert.riskcode);
      const alertName = alert.name || alert.alert || "Unknown";
      const instances = alert.instances || [{}];
      for (const inst of instances) {
        findings.push({
          alert:            alertName,
          attack_type:      alert.pluginid ? alertName + " [" + alert.pluginid + "]" : alertName,
          severity,
          endpoint:         (inst.uri  || "").slice(0, 500),
          method:           (inst.method || "GET").toUpperCase().slice(0, 10),
          param:            (inst.param  || "").slice(0, 200),
          request_payload:  (inst.attack || "").slice(0, 1000),
          response_details: (inst.evidence || "").slice(0, 1000),
          cwe_id:           alert.cweid ? Number(alert.cweid) || null : null,
          solution:         (alert.solution || "").replace(/<[^>]*>/g, "").slice(0, 1000),
        });
      }
    }
  }
  return findings;
}

function summarize(findings) {
  const s = { high: 0, medium: 0, low: 0, informational: 0, total: 0 };
  for (const f of findings) {
    s.total++;
    const sev = (f.severity || "INFORMATIONAL").toUpperCase();
    if      (sev === "HIGH")          s.high++;
    else if (sev === "MEDIUM")        s.medium++;
    else if (sev === "LOW")           s.low++;
    else                              s.informational++;
  }
  return s;
}

// ------------------------------------------------------------------ routes

// PATCH /api/dast/target/:projectId — save target_url for this project
router.patch("/target/:projectId", auth, async (req, res) => {
  try {
    const projectId = Number.parseInt(String(req.params.projectId ?? "").trim(), 10);
    if (!Number.isInteger(projectId) || projectId < 1) {
      return res.status(400).json({ error: "Invalid project id" });
    }
    const { target_url } = req.body;
    if (!target_url || typeof target_url !== "string" || !target_url.trim()) {
      return res.status(400).json({ error: "target_url is required" });
    }
    // Validate it looks like a URL
    try { new URL(target_url.trim()); } catch {
      return res.status(400).json({ error: "target_url must be a valid URL (e.g. http://localhost:3001)" });
    }

    const r = await pool.query(
      "UPDATE projects SET target_url = $1 WHERE id = $2 AND user_id = $3 RETURNING id",
      [target_url.trim(), projectId, req.user.id]
    );
    if (!r.rowCount) return res.status(404).json({ error: "Project not found" });
    return res.json({ success: true, target_url: target_url.trim() });
  } catch (error) {
    return res.status(500).json({ error: error.message || "Failed to save target URL" });
  }
});

// POST /api/dast/scan/:projectId — run ZAP baseline scan
router.post("/scan/:projectId", auth, async (req, res) => {
  const projectId = Number.parseInt(String(req.params.projectId ?? "").trim(), 10);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: "Invalid project id" });
  }

  let scanId = null;
  let reportDir = null;

  try {
    // 1. Ownership check
    const projectRes = await pool.query(
      "SELECT * FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const project = projectRes.rows[0];
    const targetUrl = project.target_url?.trim();
    if (!targetUrl) {
      return res.status(400).json({
        error: "No DAST target URL configured for this project. Set one on the DAST results page first.",
      });
    }

    // 2. Concurrent scan guard
    const runningRes = await pool.query(
      "SELECT id FROM dast_scans WHERE project_id = $1 AND status = 'RUNNING' LIMIT 1",
      [projectId]
    );
    if (runningRes.rows.length) {
      return res.status(409).json({ error: "A DAST scan is already running for this project." });
    }

    // 3. Create scan record
    const scanRow = await pool.query(
      "INSERT INTO dast_scans (project_id, target_url, status, started_at) VALUES ($1, $2, 'RUNNING', NOW()) RETURNING id",
      [projectId, targetUrl]
    );
    scanId = scanRow.rows[0].id;

    // 4. Create temp dir for ZAP report (mounted as a Docker volume)
    reportDir = fs.mkdtempSync("/tmp/zap-" + projectId + "-" + scanId + "-");
    const reportFile = path.join(reportDir, "report.json");

    // 5. Run ZAP baseline scan via Docker
    // --network host so ZAP can reach localhost (Juice Shop on port 3001)
    // -v mounts reportDir into /zap/wrk so we can read the JSON output
    // -J report.json writes JSON report; --rm cleans the container up on exit
    // Exit codes: 0=no alerts, 1=alerts found, 2=warn-only alerts — all SUCCESS
    const zapArgs = [
      "run", "--rm",
      "--network", "host",
      "-v", reportDir + ":/zap/wrk/:rw",
      ZAP_IMAGE,
      "zap-baseline.py",
      "-t", targetUrl,
      "-J", "report.json",
      "-I",              // don't fail on warn rules (exit 2 treated as success anyway)
    ];

    console.log("[dast scan=" + scanId + "] Running ZAP baseline on", targetUrl);
    await spawnWithTimeout("zap-baseline", DOCKER_CMD, zapArgs, {
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    }, DAST_TIMEOUT_MS);

    // 6. Parse ZAP JSON output
    let zapData = null;
    if (fs.existsSync(reportFile)) {
      try {
        zapData = JSON.parse(fs.readFileSync(reportFile, "utf8"));
      } catch (e) {
        console.warn("[dast scan=" + scanId + "] Failed to parse report.json:", e.message);
      }
    } else {
      console.warn("[dast scan=" + scanId + "] report.json not found at", reportFile);
    }

    const findings = zapData ? extractDastFindings(zapData) : [];
    const summary  = summarize(findings);

    // 7. Delete old findings for this project, insert new (strict project_id scoping)
    await pool.query("DELETE FROM dast_findings WHERE project_id = $1", [projectId]);

    for (const f of findings) {
      await pool.query(
        "INSERT INTO dast_findings (scan_id, project_id, alert, attack_type, severity, endpoint, method, param, request_payload, response_details, cwe_id, solution) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        [scanId, projectId, f.alert, f.attack_type, f.severity, f.endpoint,
         f.method, f.param, f.request_payload, f.response_details, f.cwe_id, f.solution]
      );
    }

    // 8. Mark scan COMPLETED
    await pool.query(
      "UPDATE dast_scans SET status = 'COMPLETED', total_findings = $1, high = $2, medium = $3, low = $4, informational = $5, completed_at = NOW() WHERE id = $6",
      [summary.total, summary.high, summary.medium, summary.low, summary.informational, scanId]
    );

    // 9. Cleanup temp report dir
    if (reportDir && fs.existsSync(reportDir)) {
      fs.rmSync(reportDir, { recursive: true, force: true });
    }

    console.log("[dast scan=" + scanId + "] Completed. Findings: " + summary.total);
    return res.json({ success: true, scanId, summary, total: summary.total });

  } catch (error) {
    console.error("[dast-scan project=" + projectId + "] Error:", error.message || error);
    if (scanId) {
      await pool.query("UPDATE dast_scans SET status = 'FAILED', completed_at = NOW() WHERE id = $1", [scanId])
        .catch((e) => console.error("[dast] failed to mark FAILED:", e.message));
    }
    if (reportDir && fs.existsSync(reportDir)) {
      fs.rmSync(reportDir, { recursive: true, force: true });
    }
    return res.status(500).json({ error: error.message || "DAST scan failed" });
  }
});

// GET /api/dast/:projectId — findings scoped strictly to this project
router.get("/:projectId", auth, async (req, res) => {
  try {
    const projectId = Number.parseInt(String(req.params.projectId ?? "").trim(), 10);
    if (!Number.isInteger(projectId) || projectId < 1) {
      return res.status(400).json({ error: "Invalid project id" });
    }

    // Ownership check + fetch target_url so the frontend can show it
    const projectRes = await pool.query(
      "SELECT id, target_url FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const latestScanRes = await pool.query(
      "SELECT id, status, target_url, total_findings, high, medium, low, informational, started_at, completed_at FROM dast_scans WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1",
      [projectId]
    );
    const latestScan = latestScanRes.rows[0] || null;

    // CRITICAL: findings strictly scoped by project_id — never omitted
    const findingsRes = await pool.query(
      "SELECT id, alert, attack_type, severity, endpoint, method, param, request_payload, response_details, cwe_id, solution, created_at FROM dast_findings WHERE project_id = $1 ORDER BY CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 WHEN 'INFORMATIONAL' THEN 4 ELSE 5 END, alert",
      [projectId]
    );

    const findings = findingsRes.rows;
    const summary = {
      high:          latestScan?.high          ?? 0,
      medium:        latestScan?.medium        ?? 0,
      low:           latestScan?.low           ?? 0,
      informational: latestScan?.informational ?? 0,
      total:         latestScan?.total_findings ?? 0,
    };

    return res.json({
      latestScan,
      findings,
      summary,
      target_url: projectRes.rows[0].target_url || null,
    });
  } catch (error) {
    console.error("[dast] GET error:", error.message || error);
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

module.exports = router;
