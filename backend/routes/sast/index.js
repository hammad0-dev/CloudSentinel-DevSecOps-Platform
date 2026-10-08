"use strict";

const express = require("express");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const pool = require("../../db");
const auth = require("../../middleware/auth");
const {
  severityOrder,
  sonarBaseUrl,
  assertSonarReachable,
  sonarAuthAxiosConfig,
  SONAR_INDEX_MAX_WAIT_MS,
  SONAR_INDEX_POLL_MS,
  continueOnBuildFailure,
  allowEmptySonarIndex,
  parseSastProjectId,
  sanitizeScanError,
  isGradleProjectLayout,
  coerceIssueRow,
  wait,
  shouldKeepClone,
} = require("./config");
const {
  resolveCloneUrl,
  useShallowGitClone,
  gitCloneAsync,
  buildJavaProjectIfPresent,
  buildGradleProjectIfPresent,
  stripSonarProjectPropertiesFromClone,
  detectedGitBranch,
  runSonarScannerAsync,
} = require("./pipeline");
const {
  OWASP_RULE_MAP,
  buildComplianceFromIssues,
  mergeDependencyIntoCompliance,
} = require("./compliance");
const { fetchSonarMetrics } = require("./metrics");

const router = express.Router();
const hasUsableProjectToken = (token) =>
  typeof token === "string" &&
  token.trim() &&
  !token.includes("your_github_pat_token_here") &&
  !token.trim().startsWith("ghp_your_");

router.post("/scan/:projectId", auth, async (req, res) => {
  const rawParam = req.params.projectId;
  const pid = parseSastProjectId(rawParam);
  if (pid == null) return res.status(400).json({ error: "Invalid project id" });

  const cloneRoot = path.resolve(process.env.CLONE_DIR || "/tmp/cloudsentinel-scans");
  const cloneTarget = path.join(cloneRoot, String(pid));
  let scanHistoryId = null;
  const continueAfterCompileFailure = continueOnBuildFailure();

  try {
    const projectRes = await pool.query("SELECT * FROM projects WHERE id = $1 AND user_id = $2", [pid, req.user.id]);
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const [runningSastRes, runningDepRes] = await Promise.all([
      pool.query(
        "SELECT id FROM scan_history WHERE project_id = $1 AND scan_type = 'SAST' AND status = 'RUNNING' LIMIT 1",
        [pid]
      ),
      pool.query(
        "SELECT id FROM dependency_scans WHERE project_id = $1 AND status = 'RUNNING' LIMIT 1",
        [pid]
      ),
    ]);
    if (runningSastRes.rows.length || runningDepRes.rows.length) {
      return res.status(409).json({
        error: "A scan is already running for this project. Please wait for it to complete.",
      });
    }

    const project = projectRes.rows[0];
    const isPrivateRepo =
      typeof project.is_private === "boolean"
        ? project.is_private
        : String(project.is_private || "").trim().toLowerCase() === "true";
    if (isPrivateRepo && !hasUsableProjectToken(project.github_token)) {
      return res.status(400).json({
        error: "Private repository scan requires a valid project GitHub token.",
      });
    }
    const cloneUrl = resolveCloneUrl(project);
    if (!String(cloneUrl || "").trim()) {
      return res.status(400).json({ error: "Project has no repository URL configured" });
    }

    const runRow = await pool.query(
      "INSERT INTO scan_history (project_id, scan_type, status, started_at) VALUES ($1, 'SAST', 'RUNNING', NOW()) RETURNING id",
      [pid]
    );
    scanHistoryId = runRow.rows[0]?.id;

    if (!fs.existsSync(cloneRoot)) fs.mkdirSync(cloneRoot, { recursive: true });
    if (fs.existsSync(cloneTarget)) fs.rmSync(cloneTarget, { recursive: true, force: true });

    await assertSonarReachable();

    const t0 = Date.now();
    const phase = (label) =>
      console.log(`[SAST project=${pid}] ${label} (+${Math.round((Date.now() - t0) / 1000)}s)`);

    await gitCloneAsync(cloneUrl, cloneTarget);
    phase(useShallowGitClone() ? "git clone finished (shallow)" : "git clone finished (full)");

    const hasPom = fs.existsSync(path.join(cloneTarget, "pom.xml"));
    if (hasPom) {
      try {
        await buildJavaProjectIfPresent(cloneTarget);
        phase("Maven build finished");
      } catch (mvnErr) {
        if (!continueAfterCompileFailure) throw mvnErr;
        console.warn(
          `[SAST project=${pid}] Maven compile failed (continuing; set SAST_CONTINUE_ON_BUILD_FAILURE=false to fail scan):`,
          mvnErr?.message || mvnErr
        );
        phase("Maven compile failed (continuing without full artifacts)");
      }
    } else {
      phase("Maven skipped (no pom.xml)");
    }

    const gradleLayout = isGradleProjectLayout(cloneTarget);
    const ranGradle = await buildGradleProjectIfPresent(cloneTarget, {
      softFail: continueAfterCompileFailure,
    });
    if (ranGradle) phase("Gradle compiled (main sources)");
    else if (gradleLayout && continueAfterCompileFailure) {
      phase("Gradle did not emit bytecode (continuing with Sonar source analysis)");
    } else phase("Gradle skipped (no Gradle project)");

    stripSonarProjectPropertiesFromClone(cloneTarget);

    const sonarHost = sonarBaseUrl();
    const branchName = detectedGitBranch(cloneTarget);
    await runSonarScannerAsync(pid, cloneTarget, sonarHost, branchName);
    phase("sonar-scanner finished");

    const projectKey = `cloudsentinel_${pid}`;
    const deadline = Date.now() + SONAR_INDEX_MAX_WAIT_MS;
    let ncloc = 0;
    let files = 0;

    while (Date.now() < deadline) {
      try {
        const measuresRes = await axios.get(
          `${sonarHost}/api/measures/component?component=${encodeURIComponent(projectKey)}&metricKeys=ncloc,files`,
          sonarAuthAxiosConfig()
        );
        const measures = measuresRes.data?.component?.measures || [];
        ncloc = Number(measures.find((m) => m.metric === "ncloc")?.value || 0);
        files = Number(measures.find((m) => m.metric === "files")?.value || 0);
      } catch (e) {
        const msg =
          axios.isAxiosError(e) && e.response
            ? `Sonar HTTP ${e.response.status}: ${JSON.stringify(e.response.data || {}).slice(0, 200)}`
            : e?.message || String(e);
        console.warn("[SAST] waiting for Sonar measures:", msg);
      }
      if (ncloc > 0 && files > 0) break;
      await wait(SONAR_INDEX_POLL_MS);
    }

    if ((!ncloc || !files) && allowEmptySonarIndex()) {
      console.warn(
        `[SAST project=${pid}] Sonar still shows 0 ncloc/files after ${Math.round(
          SONAR_INDEX_MAX_WAIT_MS / 1000
        )}s; completing with issues API only (set SAST_ALLOW_EMPTY_SONAR_INDEX=false to fail). Project key: ${projectKey}`
      );
    } else if (!ncloc || !files) {
      throw new Error(
        `SonarQube still reports 0 indexed lines/files after waiting ${Math.round(
          SONAR_INDEX_MAX_WAIT_MS / 1000
        )}s (project "${projectKey}"). Confirm SONAR_TOKEN, Sonar CE health, language plugins ` +
          `or increase SAST_SONAR_INDEX_MAX_WAIT_MS / SAST_SONAR_INDEX_POLL_MS.`
      );
    }

    const sonarRes = await axios.get(
      `${sonarHost}/api/issues/search?projectKeys=${encodeURIComponent(projectKey)}&ps=500`,
      sonarAuthAxiosConfig()
    );

    const allIssues = Array.isArray(sonarRes.data?.issues) ? sonarRes.data.issues : [];

    // Strict filter: only keep issues that belong to THIS project's SonarQube key.
    // This prevents cross-project contamination when SonarQube reuses component keys
    // across scans of different projects with the same repository.
    const issues = allIssues.filter((issue) => {
      const component = issue.component || issue.project || "";
      return component.startsWith(projectKey);
    });

    if (allIssues.length !== issues.length) {
      console.warn(
        `[SAST project=${pid}] Filtered out ${allIssues.length - issues.length} issue(s) belonging to a different SonarQube project key (expected prefix: "${projectKey}")`
      );
    }

    await pool.query("DELETE FROM scan_results WHERE project_id = $1", [pid]);

    let insertIssueErrors = 0;
    const persistedIssues = [];
    for (const issue of issues) {
      try {
        const row = coerceIssueRow(issue, pid);
        await pool.query(
          "INSERT INTO scan_results (project_id, rule, severity, message, file_path, line_number, status) VALUES ($1,$2,$3,$4,$5,$6,'OPEN')",
          row
        );
        persistedIssues.push(issue);
      } catch (insErr) {
        insertIssueErrors += 1;
        console.warn("[SAST] skipped malformed issue row:", insErr?.message || insErr);
      }
    }
    if (insertIssueErrors > 0) {
      console.warn(`[SAST project=${pid}] ${insertIssueErrors} issue row(s) skipped during insert`);
    }


    const summary = persistedIssues.reduce(
      (acc, item) => {
        const sev = (item.severity || "INFO").toUpperCase();
        if (sev === "CRITICAL") acc.critical += 1;
        else if (sev === "MAJOR" || sev === "HIGH") acc.high += 1;
        else if (sev === "MINOR" || sev === "MEDIUM" || sev === "LOW") acc.medium += 1;
        else acc.low += 1;
        acc.total += 1;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
    );

    await pool.query(
      `UPDATE scan_history SET
        status = 'COMPLETED',
        total_issues = $1,
        critical = $2,
        high = $3,
        medium = $4,
        low = $5,
        completed_at = NOW()
      WHERE id = $6`,
      [summary.total, summary.critical, summary.high, summary.medium, summary.low, scanHistoryId]
    );

    if (!shouldKeepClone() && fs.existsSync(cloneTarget)) {
      fs.rmSync(cloneTarget, { recursive: true, force: true });
    }
    return res.json({ success: true, total: summary.total, summary });
  } catch (error) {
    const message = sanitizeScanError(error);
    if (scanHistoryId != null) {
      try {
        await pool.query(
          `UPDATE scan_history SET status = 'FAILED', completed_at = NOW() WHERE id = $1`,
          [scanHistoryId]
        );
      } catch (dbErr) {
        console.error("[SAST] could not mark scan_history FAILED:", dbErr?.message || dbErr);
      }
    }
    try {
      if (!shouldKeepClone() && fs.existsSync(cloneTarget)) {
        fs.rmSync(cloneTarget, { recursive: true, force: true });
      }
    } catch (rmErr) {
      console.warn("[SAST] clone cleanup failed:", rmErr?.message || rmErr);
    }
    if (!res.headersSent) {
      return res.status(500).json({ error: message });
    }
  }
});

router.get("/compliance/:projectId", auth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const projectRes = await pool.query("SELECT id, name FROM projects WHERE id = $1 AND user_id = $2", [
      projectId,
      req.user.id,
    ]);
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const [issuesRes, depRes] = await Promise.all([
      pool.query(
        "SELECT rule, severity, message, file_path, line_number, status FROM scan_results WHERE project_id = $1 ORDER BY created_at DESC",
        [projectId]
      ),
      pool.query(
        "SELECT severity, pkg_name, cve_id FROM sbom_components WHERE project_id = $1 AND cve_id IS NOT NULL",
        [projectId]
      ),
    ]);
    const issues = issuesRes.rows;
    const dependencyFindings = depRes.rows;
    const compliance = mergeDependencyIntoCompliance(
      buildComplianceFromIssues(issues),
      dependencyFindings
    );

    const total = issues.length + dependencyFindings.length;
    const failedControls = compliance.owasp.reduce((a, c) => a + (c.findings > 0 ? 1 : 0), 0);
    const passedControls = Math.max(0, OWASP_RULE_MAP.length - failedControls);
    const complianceScore = OWASP_RULE_MAP.length
      ? Math.round((passedControls / OWASP_RULE_MAP.length) * 100)
      : 100;

    return res.json({
      project: projectRes.rows[0],
      summary: {
        totalIssues: total,
        sastFindings: issues.length,
        dependencyFindings: dependencyFindings.length,
        failedControls,
        passedControls,
        complianceScore,
        unmappedCount: compliance.unmappedCount,
      },
      owasp: compliance.owasp,
      cis: compliance.cis,
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to assemble compliance dashboard" });
  }
});

router.get("/report/:projectId", auth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const projectRes = await pool.query(
      "SELECT id, name, repo_url, language, framework, created_at FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const [issuesRes, scanRes, depRes] = await Promise.all([
      pool.query(
        "SELECT rule, severity, message, file_path, line_number, status, created_at FROM scan_results WHERE project_id = $1 ORDER BY created_at DESC",
        [projectId]
      ),
      pool.query(
        "SELECT id, scan_type, status, total_issues, critical, high, medium, low, started_at, completed_at FROM scan_history WHERE project_id = $1 ORDER BY started_at DESC LIMIT 10",
        [projectId]
      ),
      pool.query(
        "SELECT severity, pkg_name, pkg_version, cve_id, fixed_version, description FROM sbom_components WHERE project_id = $1 AND cve_id IS NOT NULL",
        [projectId]
      ),
    ]);
    const issues = issuesRes.rows;
    const dependencyFindings = depRes.rows;
    const compliance = mergeDependencyIntoCompliance(
      buildComplianceFromIssues(issues),
      dependencyFindings
    );
    const metrics = await fetchSonarMetrics(projectId).catch(() => null);
    const depCritical = dependencyFindings.filter((i) => (i.severity || "").toUpperCase() === "CRITICAL").length;
    const depHigh = dependencyFindings.filter((i) => (i.severity || "").toUpperCase() === "HIGH").length;
    const depMediumOrLow = dependencyFindings.filter((i) =>
      ["MEDIUM", "LOW", "UNKNOWN"].includes((i.severity || "").toUpperCase())
    ).length;

    return res.json({
      generatedAt: new Date().toISOString(),
      project: projectRes.rows[0],
      metrics,
      totals: {
        issues: issues.length + dependencyFindings.length,
        sastFindings: issues.length,
        dependencyFindings: dependencyFindings.length,
        critical:
          issues.filter((i) => (i.severity || "").toUpperCase() === "CRITICAL").length + depCritical,
        high:
          issues.filter((i) => ["HIGH", "MAJOR"].includes((i.severity || "").toUpperCase())).length + depHigh,
        medium:
          issues.filter((i) => ["MEDIUM", "MINOR", "LOW"].includes((i.severity || "").toUpperCase())).length +
          depMediumOrLow,
      },
      compliance,
      scans: scanRes.rows,
      topFindings: issues.slice(0, 50),
      dependencyTopFindings: dependencyFindings.slice(0, 50),
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to generate security report" });
  }
});

router.get("/analytics/overview", auth, async (req, res) => {
  try {
    const projectsRes = await pool.query(
      "SELECT id, name, language, created_at FROM projects WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    const projects = projectsRes.rows;
    if (!projects.length) {
      return res.json({
        totals: { projects: 0, critical: 0, high: 0, medium: 0, low: 0 },
        trend: [],
        topProjects: [],
      });
    }

    const ids = projects.map((p) => p.id);
    const scansRes = await pool.query(
      `SELECT project_id, status, critical, high, medium, low, started_at, completed_at
       FROM scan_history
       WHERE project_id = ANY($1::int[])`,
      [ids]
    );

    const latestByProject = new Map();
    scansRes.rows.forEach((s) => {
      const curr = latestByProject.get(s.project_id);
      const t = new Date(s.started_at).getTime();
      if (!curr || t > new Date(curr.started_at).getTime()) latestByProject.set(s.project_id, s);
    });

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    latestByProject.forEach((s) => {
      critical += Number(s.critical || 0);
      high += Number(s.high || 0);
      medium += Number(s.medium || 0);
      low += Number(s.low || 0);
    });

    const topProjects = projects
      .map((p) => ({ ...p, latest: latestByProject.get(p.id) || null }))
      .sort((a, b) => {
        const ac = Number(a.latest?.critical || 0);
        const bc = Number(b.latest?.critical || 0);
        if (bc !== ac) return bc - ac;
        const ah = Number(a.latest?.high || 0);
        const bh = Number(b.latest?.high || 0);
        return bh - ah;
      })
      .slice(0, 8);

    return res.json({
      totals: { projects: projects.length, critical, high, medium, low },
      topProjects,
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to load analytics overview" });
  }
});

router.get("/:projectId", auth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const projectRes = await pool.query("SELECT id FROM projects WHERE id = $1 AND user_id = $2", [projectId, req.user.id]);
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const rows = await pool.query(
      "SELECT * FROM scan_results WHERE project_id = $1 ORDER BY created_at DESC",
      [projectId]
    );
    const lastScanRes = await pool.query(
      "SELECT completed_at FROM scan_history WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1",
      [projectId]
    );

    const summary = rows.rows.reduce(
      (acc, item) => {
        const sev = item.severity?.toUpperCase();
        if (sev === "CRITICAL") acc.critical += 1;
        else if (sev === "MAJOR" || sev === "HIGH") acc.major += 1;
        else if (sev === "MINOR" || sev === "LOW") acc.minor += 1;
        else acc.info += 1;
        acc.total += 1;
        return acc;
      },
      { critical: 0, major: 0, minor: 0, info: 0, total: 0 }
    );

    const vulnerabilities = rows.rows.sort((a, b) => {
      const pa = severityOrder[(a.severity || "INFO").toUpperCase()] || 99;
      const pb = severityOrder[(b.severity || "INFO").toUpperCase()] || 99;
      return pa - pb;
    });

    let sonarMetrics = null;
    try {
      sonarMetrics = await fetchSonarMetrics(projectId);
    } catch {
      sonarMetrics = null;
    }

    return res.json({
      summary,
      vulnerabilities,
      lastScan: lastScanRes.rows[0]?.completed_at || null,
      sonarMetrics,
    });
  } catch (error) {
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

module.exports = router;
