"use strict";

const express = require("express");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const pool = require("../db");
const auth = require("../middleware/auth");

const router = express.Router();

const TRIVY_CMD = process.env.TRIVY_CMD || "trivy";
const CLONE_DIR = () => path.resolve(process.env.CLONE_DIR || "/tmp/cloudsentinel-scans");

const hasUsableProjectToken = (token) =>
  typeof token === "string" &&
  token.trim() &&
  !token.includes("your_github_pat_token_here") &&
  !token.trim().startsWith("ghp_your_");

function parseEnvMs(raw, fallback) {
  const n = Number.parseInt(String(raw ?? "").trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const IAC_GIT_TIMEOUT_MS   = parseEnvMs(process.env.IAC_GIT_TIMEOUT_MS,   900000);
const IAC_TRIVY_TIMEOUT_MS = parseEnvMs(process.env.IAC_TRIVY_TIMEOUT_MS, 3600000);

const gitEnv = () => {
  const base = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
  if (process.platform !== "win32") base.GIT_ASKPASS = "/bin/false";
  return base;
};

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
      // trivy config exits 1 when misconfigs found -- that is SUCCESS for us
      if (code === 0 || code === 1) resolve({ stdout, stderr });
      else reject(new Error((stderr || stdout || label + " exited " + code).trim()));
    });
  });
}

function parseTrivyJson(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

function extractIacFindings(trivyData) {
  const findings = [];
  const results = trivyData?.Results || [];
  for (const result of results) {
    const configFile = result.Target || "unknown";
    const misconfigs = result.Misconfigurations || [];
    for (const m of misconfigs) {
      findings.push({
        config_file:    configFile,
        misconfig_type: m.Title  || m.ID || "Unknown",
        misconfig_id:   m.ID     || null,
        severity:       (m.Severity || "UNKNOWN").toUpperCase(),
        description:    (m.Description || "").slice(0, 500) || null,
        resolution:     (m.Resolution  || "").slice(0, 500) || null,
        start_line:     m.CauseMetadata?.StartLine ?? null,
      });
    }
  }
  return findings;
}

function summarize(findings) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 };
  for (const f of findings) {
    s.total++;
    const sev = (f.severity || "UNKNOWN").toUpperCase();
    if      (sev === "CRITICAL") s.critical++;
    else if (sev === "HIGH")     s.high++;
    else if (sev === "MEDIUM")   s.medium++;
    else if (sev === "LOW")      s.low++;
    else                         s.unknown++;
  }
  return s;
}

// POST /api/iac/scan/:projectId
router.post("/scan/:projectId", auth, async (req, res) => {
  const projectId = Number.parseInt(String(req.params.projectId ?? "").trim(), 10);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: "Invalid project id" });
  }

  let scanId = null;
  let cloneTarget = null;

  try {
    const projectRes = await pool.query(
      "SELECT * FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const runningRes = await pool.query(
      "SELECT id FROM iac_scans WHERE project_id = $1 AND status = 'RUNNING' LIMIT 1",
      [projectId]
    );
    if (runningRes.rows.length) {
      return res.status(409).json({ error: "An IaC scan is already running for this project." });
    }

    const project = projectRes.rows[0];
    const isPrivateRepo =
      typeof project.is_private === "boolean"
        ? project.is_private
        : String(project.is_private || "").trim().toLowerCase() === "true";

    if (isPrivateRepo && !hasUsableProjectToken(project.github_token)) {
      return res.status(400).json({ error: "Private repository scan requires a valid project GitHub token." });
    }

    const scanRow = await pool.query(
      "INSERT INTO iac_scans (project_id, status, started_at) VALUES ($1, 'RUNNING', NOW()) RETURNING id",
      [projectId]
    );
    scanId = scanRow.rows[0].id;

    const cloneRoot = CLONE_DIR();
    if (!fs.existsSync(cloneRoot)) fs.mkdirSync(cloneRoot, { recursive: true });
    cloneTarget = fs.mkdtempSync(path.join(cloneRoot, projectId + "-iac-"));

    const token = isPrivateRepo
      ? (hasUsableProjectToken(project.github_token) ? project.github_token.trim() : null)
      : (project.github_token?.trim() || process.env.GITHUB_TOKEN?.trim() || null);

    let cloneUrl = project.repo_url;
    if (token && /^https:\/\/(www\.)?github\.com\//i.test(cloneUrl)) {
      const u = new URL(cloneUrl);
      u.username = "x-access-token";
      u.password = token;
      cloneUrl = u.href;
    }

    await spawnWithTimeout(
      "git clone (iac)",
      "git",
      ["clone", "--depth", "1", cloneUrl, cloneTarget],
      { env: gitEnv(), stdio: ["ignore", "pipe", "pipe"], shell: process.platform === "win32" },
      IAC_GIT_TIMEOUT_MS
    );

    const trivyResult = await spawnWithTimeout(
      "trivy config (iac)",
      TRIVY_CMD,
      ["config", "--format", "json", "--exit-code", "1", cloneTarget],
      {
        cwd: cloneTarget,
        env: { ...process.env, TRIVY_NO_PROGRESS: "true" },
        stdio: ["ignore", "pipe", "pipe"],
        shell: process.platform === "win32",
      },
      IAC_TRIVY_TIMEOUT_MS
    );

    const trivyRaw = typeof trivyResult === "object" ? trivyResult.stdout : trivyResult;
    const trivyData = parseTrivyJson((trivyRaw || "").trim());

    if (!trivyData && (trivyRaw || "").length > 0) {
      console.warn("[iac-scan] Trivy stdout was not valid JSON:", String(trivyRaw).slice(0, 300));
    }

    const findings = trivyData ? extractIacFindings(trivyData) : [];
    const summary  = summarize(findings);

    await pool.query("DELETE FROM iac_findings WHERE project_id = $1", [projectId]);

    for (const f of findings) {
      await pool.query(
        "INSERT INTO iac_findings (scan_id, project_id, config_file, misconfig_type, misconfig_id, severity, description, resolution, start_line) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        [scanId, projectId, f.config_file, f.misconfig_type, f.misconfig_id, f.severity, f.description, f.resolution, f.start_line]
      );
    }

    await pool.query(
      "UPDATE iac_scans SET status = 'COMPLETED', total_findings = $1, critical = $2, high = $3, medium = $4, low = $5, unknown = $6, completed_at = NOW() WHERE id = $7",
      [summary.total, summary.critical, summary.high, summary.medium, summary.low, summary.unknown, scanId]
    );

    if (fs.existsSync(cloneTarget)) fs.rmSync(cloneTarget, { recursive: true, force: true });
    return res.json({ success: true, scanId, summary, total: summary.total });

  } catch (error) {
    console.error("[iac-scan project=" + projectId + "] Error:", error.message || error);
    if (scanId) {
      await pool.query("UPDATE iac_scans SET status = 'FAILED', completed_at = NOW() WHERE id = $1", [scanId])
        .catch((e) => console.error("[iac-scan] failed to mark FAILED:", e.message));
    }
    if (cloneTarget && fs.existsSync(cloneTarget)) {
      fs.rmSync(cloneTarget, { recursive: true, force: true });
    }
    return res.status(500).json({ error: error.message || "IaC scan failed" });
  }
});

// GET /api/iac/:projectId
// CRITICAL: both ownership check AND findings query use project_id = $1 -- no cross-project leakage possible.
router.get("/:projectId", auth, async (req, res) => {
  try {
    const projectId = Number.parseInt(String(req.params.projectId ?? "").trim(), 10);
    if (!Number.isInteger(projectId) || projectId < 1) {
      return res.status(400).json({ error: "Invalid project id" });
    }

    const projectRes = await pool.query(
      "SELECT id FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const scanRes = await pool.query(
      "SELECT id, status, total_findings, critical, high, medium, low, unknown, started_at, completed_at FROM iac_scans WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1",
      [projectId]
    );
    const latestScan = scanRes.rows[0] || null;

    const findingsRes = await pool.query(
      "SELECT id, config_file, misconfig_type, misconfig_id, severity, description, resolution, start_line, created_at FROM iac_findings WHERE project_id = $1 ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, config_file",
      [projectId]
    );

    const findings = findingsRes.rows;
    const summary = {
      critical: latestScan?.critical ?? 0,
      high:     latestScan?.high     ?? 0,
      medium:   latestScan?.medium   ?? 0,
      low:      latestScan?.low      ?? 0,
      unknown:  latestScan?.unknown  ?? 0,
      total:    latestScan?.total_findings ?? 0,
    };

    return res.json({ latestScan, findings, summary });
  } catch (error) {
    console.error("[iac] GET error:", error.message || error);
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

module.exports = router;
