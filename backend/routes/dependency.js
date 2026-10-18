const express = require("express");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const pool = require("../db");
const auth = require("../middleware/auth");
const { resolvePipelineExecutionId } = require("../services/pipelineExecutionContext");

const { configuration: dependencyConfiguration, coverage: dependencyCoverage } = require("../services/dependencyRuntime");
const router = express.Router();

const TRIVY_CMD = process.env.TRIVY_CMD || "trivy";
const hasUsableProjectToken = (token) =>
  typeof token === "string" &&
  token.trim() &&
  !token.includes("your_github_pat_token_here") &&
  !token.trim().startsWith("ghp_your_");

function parseEnvMs(raw, fallback) {
  const n = Number.parseInt(String(raw ?? "").trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const DEP_GIT_TIMEOUT_MS = parseEnvMs(process.env.DEP_GIT_TIMEOUT_MS, 900_000);
const DEP_TRIVY_TIMEOUT_MS = parseEnvMs(process.env.DEP_TRIVY_TIMEOUT_MS, 3_600_000);
/** Gradle-only repos (no gradle.lockfile): Trivy fs rarely finds deps from bare build.gradle; compile emits jars/poms under build/ for scanning. Set DEP_SKIP_GRADLE_COMPILE=true to skip. */
const DEP_GRADLE_COMPILE_TIMEOUT_MS = parseEnvMs(process.env.DEP_GRADLE_COMPILE_TIMEOUT_MS, 900_000);

const SKIP_GRADLE_COMPILE = /^true$/i.test(String(process.env.DEP_SKIP_GRADLE_COMPILE ?? "").trim());

const gitEnv = () => {
  const base = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
  if (process.platform !== "win32") base.GIT_ASKPASS = "/bin/false";
  return base;
};

/** Kill child on timeout — avoids RUNNING dependency scans stuck forever (hung git/trivy). */
function spawnWithTimeout(label, command, args, spawnOptions, timeoutMs) {
  return new Promise((resolve, reject) => {
    const options = { ...spawnOptions };
    if (process.platform !== "win32") options.detached = true;
    const child = spawn(command, args, options);
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let killTimer;
    const terminateGroup = (signal) => {
      try {
        if (process.platform !== "win32" && child.pid) process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch (_) { try { child.kill(signal); } catch (_) {} }
    };
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      terminateGroup("SIGTERM");
      killTimer = setTimeout(() => terminateGroup("SIGKILL"), 2000);
    }, timeoutMs);

    child.stdout?.on("data", (c) => {
      stdout += c;
    });
    child.stderr?.on("data", (c) => {
      stderr += c;
    });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
      if (timedOut) {
        reject(new Error(`${label}: timed out after ${Math.round(timeoutMs / 1000)}s.`));
        return;
      }
      reject(err);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
      if (timedOut) {
        reject(new Error(`${label}: timed out after ${Math.round(timeoutMs / 1000)}s.`));
        return;
      }
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error((stderr || stdout || `${label} exited ${code}`).trim()));
    });
  });
}

function gradleJvmEnv() {
  const env = { ...process.env };
  const jh =
    process.env.DEP_GRADLE_JAVA_HOME?.trim() ||
    process.env.SAST_GRADLE_JAVA_HOME?.trim();
  if (jh) {
    env.JAVA_HOME = jh;
    env.PATH = `${path.join(jh, "bin")}${path.delimiter}${env.PATH || ""}`;
  }
  return env;
}

/**
 * Gradle projects without pom.xml / *.gradle.lockfile: run compileJava so Trivy sees resolved artifacts under build/.
 * Non-fatal on failure — Trivy still runs against sources (often still sparse for Gradle-only).
 */
async function bestEffortGradleCompileForTrivy(runDir) {
  if (SKIP_GRADLE_COMPILE) return;

  const hasPom = fs.existsSync(path.join(runDir, "pom.xml"));
  const hasGradle =
    fs.existsSync(path.join(runDir, "build.gradle")) ||
    fs.existsSync(path.join(runDir, "build.gradle.kts"));
  if (!hasGradle || hasPom) return;

  const unixGradlew = path.join(runDir, "gradlew");
  const bat = path.join(runDir, "gradlew.bat");
  const hasUnix = fs.existsSync(unixGradlew);
  const hasBat = fs.existsSync(bat);
  if (!hasUnix && !hasBat) {
    console.warn("[dep-scan] Gradle project without gradlew; skipping compile step.");
    return;
  }

  if (process.platform !== "win32" && hasUnix) {
    try {
      fs.chmodSync(unixGradlew, 0o755);
    } catch {
      /* non-fatal */
    }
  }

  const tasks = ["compileJava", "-x", "test"];
  const gEnv = gradleJvmEnv();

  try {
    if (process.platform === "win32" && hasBat) {
      await spawnWithTimeout(
        "gradlew compileJava (deps)",
        "gradlew.bat",
        tasks,
        { cwd: runDir, env: gEnv, stdio: ["ignore", "pipe", "pipe"], shell: true },
        DEP_GRADLE_COMPILE_TIMEOUT_MS
      );
    } else if (process.platform === "win32" && hasUnix && !hasBat) {
      await spawnWithTimeout(
        "bash gradlew compileJava (deps)",
        "bash",
        [unixGradlew, ...tasks],
        { cwd: runDir, env: gEnv, stdio: ["ignore", "pipe", "pipe"], shell: false },
        DEP_GRADLE_COMPILE_TIMEOUT_MS
      );
    } else if (hasUnix) {
      await spawnWithTimeout(
        "gradlew compileJava (deps)",
        unixGradlew,
        tasks,
        { cwd: runDir, env: gEnv, stdio: ["ignore", "pipe", "pipe"], shell: false },
        DEP_GRADLE_COMPILE_TIMEOUT_MS
      );
    } else if (hasBat) {
      await spawnWithTimeout(
        "gradlew.bat compileJava (deps)",
        "gradlew.bat",
        tasks,
        { cwd: runDir, env: gEnv, stdio: ["ignore", "pipe", "pipe"], shell: true },
        DEP_GRADLE_COMPILE_TIMEOUT_MS
      );
    }
    console.warn("[dep-scan] Gradle compileJava finished; Trivy should see build/ artifacts.");
  } catch (e) {
    console.warn(
      "[dep-scan] Gradle compileJava skipped or failed (Trivy may still report 0 Java libs):",
      e?.message || e
    );
  }
}

function runTrivy(args, cwd) {
  return spawnWithTimeout(
    "trivy",
    TRIVY_CMD,
    args,
    {
      cwd: cwd || process.cwd(),
      env: dependencyConfiguration().env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32",
    },
    DEP_TRIVY_TIMEOUT_MS
  ).then(({ stdout, stderr }) => ({ stdout, stderr: stderr?.trim?.() ?? stderr }));
}

const TRIVY_FS_COMMON = ["fs", "--format", "json", "--scanners", "vuln,license", "--list-all-pkgs", "."];

function parseTrivyJson(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function summarize(components) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 };
  components.forEach((c) => {
    const sev = (c.severity || "UNKNOWN").toUpperCase();
    s.total++;
    if (sev === "CRITICAL") s.critical++;
    else if (sev === "HIGH") s.high++;
    else if (sev === "MEDIUM") s.medium++;
    else if (sev === "LOW") s.low++;
    else s.unknown++;
  });
  return s;
}

function extractComponents(trivyData) {
  const components = [];
  const results = trivyData?.Results || [];
  results.forEach((result) => {
    const packages = result.Packages || [];
    const vulns = result.Vulnerabilities || [];

    // Trivy fs JSON frequently contains Vulnerabilities without Packages.
    // Always ingest vulnerability rows directly so CVEs are not dropped.
    vulns.forEach((v) => {
      components.push({
        pkg_name: v.PkgName || "unknown",
        pkg_version: v.InstalledVersion || "",
        pkg_type: result.Type || "unknown",
        license: null,
        cve_id: v.VulnerabilityID || null,
        severity: v.Severity || "UNKNOWN",
        cvss_score: v.CVSS?.nvd?.V3Score || v.CVSS?.redhat?.V3Score || null,
        fixed_version: v.FixedVersion || null,
        description: v.Description
          ? v.Description.slice(0, 300)
          : (v.Title || null),
      });
    });

    const pkgVulnMap = {};
    vulns.forEach((v) => {
      const key = `${v.PkgName}@${v.InstalledVersion}`;
      if (!pkgVulnMap[key]) pkgVulnMap[key] = [];
      pkgVulnMap[key].push(v);
    });

    packages.forEach((pkg) => {
      const key = `${pkg.Name}@${pkg.Version}`;
      const pkgVulns = pkgVulnMap[key] || [];
      if (pkgVulns.length === 0) {
        components.push({
          pkg_name: pkg.Name,
          pkg_version: pkg.Version || "",
          pkg_type: result.Type || "unknown",
          license: (pkg.Licenses || []).join(", ") || null,
          cve_id: null,
          severity: "NONE",
          cvss_score: null,
          fixed_version: null,
          description: null,
        });
      }
    });
  });
  return components;
}

// POST /api/dependencies/scan/:projectId
// Clone repo (or reuse existing) then run trivy fs on it.
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

    const pipelineExecutionId = await resolvePipelineExecutionId(pool, req.user, projectId);

    const [runningSastRes, runningDepRes] = await Promise.all([
      pool.query(
        "SELECT id FROM scan_history WHERE project_id = $1 AND scan_type = 'SAST' AND status = 'RUNNING' LIMIT 1",
        [projectId]
      ),
      pool.query(
        "SELECT id FROM dependency_scans WHERE project_id = $1 AND status = 'RUNNING' LIMIT 1",
        [projectId]
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

    const runRow = await pool.query(
      "INSERT INTO dependency_scans (project_id, pipeline_execution_id, status, target_type, started_at) VALUES ($1, $2, 'RUNNING', 'fs', NOW()) RETURNING id",
      [projectId, pipelineExecutionId]
    );
    scanId = runRow.rows[0].id;

    const cloneRoot = dependencyConfiguration().checkoutRoot;

    if (!fs.existsSync(cloneRoot)) {
      fs.mkdirSync(cloneRoot, { recursive: true, mode: 0o700 });
    }
    cloneTarget = fs.mkdtempSync(path.join(cloneRoot, `${projectId}-dep-`));
    const runDir = cloneTarget;

    const token = isPrivateRepo
      ? (hasUsableProjectToken(project.github_token) ? project.github_token.trim() : null)
      : (project.github_token?.trim() || (process.env.GITHUB_TOKEN?.trim() || null));
    let cloneUrl = project.repo_url;
    if (token && /^https:\/\/(www\.)?github\.com\//i.test(cloneUrl)) {
      const u = new URL(cloneUrl);
      u.username = "x-access-token";
      u.password = token;
      cloneUrl = u.href;
    }
    await spawnWithTimeout(
      "git clone (dependencies)",
      "git",
      ["clone", "--depth", "1", cloneUrl, runDir],
      {
        env: gitEnv(),
        stdio: ["ignore", "pipe", "pipe"],
        shell: process.platform === "win32",
      },
      DEP_GIT_TIMEOUT_MS
    );

    const provenance=await require('../services/stageProvenance').prepare(pool,{projectId,executionId:pipelineExecutionId,userId:req.user.id},runDir);
    await bestEffortGradleCompileForTrivy(runDir);

    // Run trivy filesystem scan with JSON output + SBOM CycloneDX (--list-all-pkgs fills package rows without CVEs)
    const fsScan = await runTrivy(TRIVY_FS_COMMON, runDir);
    const trivyFsJson = typeof fsScan === "object" ? fsScan.stdout : fsScan;

    const trivyData = parseTrivyJson(trivyFsJson || "");
    if (!trivyData || trivyData.SchemaVersion !== 2 || !Array.isArray(trivyData.Results)) throw new Error("Invalid Trivy vulnerability report");
    const sb = await runTrivy(["fs", "--format", "cyclonedx", "--scanners", "vuln,license", "."], runDir);
    const sbomOutput = sb.stdout;
    const bom = parseTrivyJson(sbomOutput);
    if (!bom || bom.bomFormat !== "CycloneDX" || !Array.isArray(bom.components)) throw new Error("Invalid CycloneDX SBOM");
    const coverage = dependencyCoverage(runDir, trivyData);
    if (coverage.status === "MANIFESTS_WITHOUT_INVENTORY") throw new Error("Dependency coverage incomplete: manifests found but no package inventory");
    const components = trivyData ? extractComponents(trivyData) : [];
    const summary = summarize(components);

    if (components.length === 0 && trivyData) {
      const errTail = typeof fsScan === "object" && fsScan.stderr ? String(fsScan.stderr).slice(0, 800) : "";
      console.warn(
        "[dep-scan] Trivy returned 0 components. Gradle/Java often need JDK 17 (SAST_GRADLE_JAVA_HOME), " +
          "or a *.gradle.lockfile / pom.xml. Trivy stderr (tail):",
        errTail || "(empty)"
      );
    }
    if (!trivyData && (trivyFsJson || "").length > 0) {
      console.warn("[dep-scan] Trivy stdout was not valid JSON (first 200 chars):", String(trivyFsJson).slice(0, 200));
    }

    await pool.query("DELETE FROM sbom_components WHERE project_id = $1 AND scan_id = $2", [projectId, scanId]);

    for (const c of components) {
      await pool.query(
        `INSERT INTO sbom_components
          (scan_id, project_id, pkg_name, pkg_version, pkg_type, license, cve_id, severity, cvss_score, fixed_version, description)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [scanId, projectId, c.pkg_name, c.pkg_version, c.pkg_type, c.license, c.cve_id, c.severity, c.cvss_score, c.fixed_version, c.description]
      );
    }

    await pool.query(
      `UPDATE dependency_scans SET
        status = 'COMPLETED',
        total_packages = $1,
        critical = $2, high = $3, medium = $4, low = $5, unknown = $6,
        sbom_json = $7,
        completed_at = NOW()
       WHERE id = $8`,
      [components.length, summary.critical, summary.high, summary.medium, summary.low, summary.unknown, sbomOutput, scanId]
    );

    if(provenance?.artifact)await require('../services/stageProvenance').attest(pool,{projectId,executionId:pipelineExecutionId,userId:req.user.id},'Dependency',scanId,{commit:provenance.commit_sha,reports:[{kind:'trivy-vulnerabilities',bytes:Buffer.from(trivyFsJson)},{kind:'cyclonedx',bytes:Buffer.from(sbomOutput)}],reportHash:require('../services/deploymentEligibility').digest({trivyData,bom,coverage}),tool:await require('../services/stageProvenance').toolVersion(TRIVY_CMD),sbomVerified:true,coverage,counts:require('../services/stageProvenance').counts(summary)});
    if (fs.existsSync(cloneTarget)) {
      fs.rmSync(cloneTarget, { recursive: true, force: true });
    }
    return res.json({ success: true, scanId, summary, total: components.length, coverage });
  } catch (error) {
    if (scanId) {
      await pool.query(
        "UPDATE dependency_scans SET status = 'FAILED', completed_at = NOW() WHERE id = $1",
        [scanId]
      );
    }
    if (cloneTarget && fs.existsSync(cloneTarget)) {
      fs.rmSync(cloneTarget, { recursive: true, force: true });
    }
    return res.status(500).json({ error: error.message || "Dependency scan failed" });
  }
});

// GET /api/dependencies/:projectId — latest results + summary
router.get("/:projectId", auth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const projectRes = await pool.query(
      "SELECT id FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const scanRes = await pool.query(
      "SELECT id, status, total_packages, critical, high, medium, low, unknown, started_at, completed_at FROM dependency_scans WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1",
      [projectId]
    );
    const latestScan = scanRes.rows[0] || null;

    const componentsRes = await pool.query(
      "SELECT pkg_name, pkg_version, pkg_type, license, cve_id, severity, cvss_score, fixed_version, description FROM sbom_components WHERE project_id = $1 ORDER BY severity, pkg_name",
      [projectId]
    );

    const vulnerable = componentsRes.rows.filter((c) => c.cve_id);
    const packages = componentsRes.rows;

    const licenseMap = {};
    packages.forEach((p) => {
      const lic = p.license || "Unknown";
      licenseMap[lic] = (licenseMap[lic] || 0) + 1;
    });
    const licenses = Object.entries(licenseMap).map(([name, value]) => ({ name, value }));

    return res.json({ latestScan, packages, vulnerable, licenses });
  } catch (error) {
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

// GET /api/dependencies/sbom/:projectId — download latest SBOM JSON (CycloneDX)
router.get("/sbom/:projectId", auth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const projectRes = await pool.query(
      "SELECT name FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const scanRes = await pool.query(
      "SELECT sbom_json, completed_at FROM dependency_scans WHERE project_id = $1 AND status = 'COMPLETED' ORDER BY started_at DESC LIMIT 1",
      [projectId]
    );
    if (!scanRes.rows.length || !scanRes.rows[0].sbom_json) {
      return res.status(404).json({ error: "No SBOM available. Run a scan first." });
    }

    const projectName = projectRes.rows[0].name.replace(/[^a-z0-9-_]/gi, "_");
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="sbom-${projectName}.json"`);
    return res.send(scanRes.rows[0].sbom_json);
  } catch (error) {
    return res.status(500).json({ error: "Failed to export SBOM" });
  }
});

// GET /api/dependencies/report/:projectId — full report payload
router.get("/report/:projectId", auth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const projectRes = await pool.query(
      "SELECT id, name, repo_url, language FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });

    const scanRes = await pool.query(
      "SELECT id, status, total_packages, critical, high, medium, low, unknown, started_at, completed_at FROM dependency_scans WHERE project_id = $1 ORDER BY started_at DESC LIMIT 5",
      [projectId]
    );
    const componentsRes = await pool.query(
      "SELECT pkg_name, pkg_version, pkg_type, license, cve_id, severity, cvss_score, fixed_version, description FROM sbom_components WHERE project_id = $1 ORDER BY severity",
      [projectId]
    );

    return res.json({
      generatedAt: new Date().toISOString(),
      project: projectRes.rows[0],
      scans: scanRes.rows,
      summary: scanRes.rows[0] || null,
      components: componentsRes.rows,
      vulnerable: componentsRes.rows.filter((c) => c.cve_id),
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to generate report" });
  }
});

router.spawnWithTimeout = spawnWithTimeout;
module.exports = router;
