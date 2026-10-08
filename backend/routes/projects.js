const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const pool = require("../db");
const auth = require("../middleware/auth");

const router = express.Router();

const parseGithubUrl = (repoUrl) => {
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/.]+)(?:\.git)?$/i);
  if (!match) return null;
  return { owner: match[1], repo: match[2] };
};

const detectFromPackageJson = (pkg) => {
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const has = (name) => Object.prototype.hasOwnProperty.call(deps, name);
  let framework = null;
  let database = null;

  if (has("express")) framework = "Express.js";
  else if (has("react")) framework = "React";
  else if (has("next")) framework = "Next.js";
  else if (has("vue")) framework = "Vue.js";
  else if (has("@nestjs/core")) framework = "NestJS";

  if (has("pg")) database = "PostgreSQL";
  else if (has("mysql2")) database = "MySQL";
  else if (has("mongoose")) database = "MongoDB";
  else if (has("redis")) database = "Redis";

  return { framework, database };
};

const getLatestScanSummary = async (projectId) => {
  const result = await pool.query(
    "SELECT status, total_issues, critical, high, medium, low, completed_at FROM scan_history WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1",
    [projectId]
  );
  return result.rows[0] || null;
};

const isUsableGithubToken = (token) => {
  if (!token || typeof token !== "string") return false;
  const t = token.trim();
  if (!t) return false;
  if (t.includes("your_github_pat_token_here")) return false;
  if (t.startsWith("ghp_your_")) return false;
  return true;
};

const normalizeRepoPrivacy = (value) => {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value.trim().toLowerCase() === "true";
  return Boolean(value);
};

const analyzeRepository = async (repoUrl, githubToken) => {
  const parsed = parseGithubUrl(repoUrl);
  if (!parsed) {
    const error = new Error("Please enter a valid GitHub repository URL.");
    error.status = 400;
    throw error;
  }

  const configuredToken = isUsableGithubToken(githubToken)
    ? githubToken
    : isUsableGithubToken(process.env.GITHUB_TOKEN)
    ? process.env.GITHUB_TOKEN
    : null;
  const headers = configuredToken ? { Authorization: `Bearer ${configuredToken}` } : {};

  let repoData;
  try {
    const repoResponse = await axios.get(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}`,
      { headers }
    );
    repoData = repoResponse.data;
  } catch (error) {
    if ([401, 403].includes(error.response?.status) && configuredToken) {
      // Retry once without auth; useful when env token is invalid but repo is public.
      try {
        const retryRes = await axios.get(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`);
        repoData = retryRes.data;
      } catch (retryError) {
        if (retryError.response?.status === 404) {
          const customError = new Error("Repository not found");
          customError.status = 404;
          throw customError;
        }
        if ([401, 403].includes(retryError.response?.status)) {
          const customError = new Error("Access denied - provide GitHub token");
          customError.status = 403;
          throw customError;
        }
        const customError = new Error("Failed to fetch repository metadata");
        customError.status = 500;
        throw customError;
      }
    } else {
      if (error.response?.status === 404) {
        const customError = new Error("Repository not found");
        customError.status = 404;
        throw customError;
      }
      if ([401, 403].includes(error.response?.status)) {
        const customError = new Error("Access denied - provide GitHub token");
        customError.status = 403;
        throw customError;
      }
      const customError = new Error("Failed to fetch repository metadata");
      customError.status = 500;
      throw customError;
    }
  }

  let language = repoData.language || null;
  let framework = null;
  let databaseTech = null;

  const candidates = ["package.json", "requirements.txt", "pom.xml", "build.gradle"];
  for (const file of candidates) {
    try {
      const fileRes = await axios.get(
        `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/contents/${file}`,
        { headers }
      );
      if (file === "package.json") {
        const content = Buffer.from(fileRes.data.content, "base64").toString("utf8");
        const pkg = JSON.parse(content);
        const detected = detectFromPackageJson(pkg);
        framework = detected.framework;
        databaseTech = detected.database;
        language = language || "JavaScript";
      } else if (file === "requirements.txt") {
        language = language || "Python";
        framework = framework || "Python";
      } else if (file === "pom.xml" || file === "build.gradle") {
        language = language || "Java";
        framework = framework || "Spring";
      }
    } catch (error) {
      // File not found is expected for many repositories.
    }
  }

  return {
    repoData,
    stack: { language, framework, database: databaseTech },
  };
};

router.post("/analyze", auth, async (req, res) => {
  try {
    const { repoUrl, githubToken } = req.body;
    if (!repoUrl) return res.status(400).json({ error: "Repository URL is required" });

    const analysis = await analyzeRepository(repoUrl, githubToken);
    return res.json({
      success: true,
      repo: {
        name: analysis.repoData.name,
        fullName: analysis.repoData.full_name,
        private: analysis.repoData.private,
        language: analysis.repoData.language,
      },
      stack: analysis.stack,
    });
  } catch (error) {
    return res.status(error.status || 500).json({ error: error.message || "Server error. Please try again." });
  }
});

router.post("/", auth, async (req, res) => {
  try {
    const name = req.body.name || req.body.projectName;
    const repoUrl = req.body.repoUrl || req.body.repositoryUrl;
    const description = req.body.description || null;
    const githubToken = req.body.githubToken;
    if (!name || !repoUrl) return res.status(400).json({ error: "Name and repository URL are required" });
    const analysis = await analyzeRepository(repoUrl, githubToken);
    const language = analysis.stack.language || "Unknown";
    const framework = analysis.stack.framework || null;
    const databaseTech = analysis.stack.database || null;
    const repoData = analysis.repoData;
    const isPrivateRepo = normalizeRepoPrivacy(repoData?.private);
    if (isPrivateRepo && !isUsableGithubToken(githubToken)) {
      return res.status(400).json({
        error: "Private repositories require a valid GitHub token when adding the project.",
      });
    }

    // Generate Webhook Secret
    const webhookSecret = crypto.randomBytes(16).toString("hex");
    let webhookId = null;

    // Attempt to register webhook with GitHub
    if (isUsableGithubToken(githubToken)) {
      try {
        const parsed = parseGithubUrl(repoUrl);
        const webhookUrl = process.env.PUBLIC_URL 
          ? `${process.env.PUBLIC_URL}/api/webhooks/github` 
          : "http://localhost:3000/api/webhooks/github"; // Fallback for local testing
          
        const hookRes = await axios.post(
          `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/hooks`,
          {
            name: "web",
            active: true,
            events: ["push"],
            config: {
              url: webhookUrl,
              content_type: "json",
              secret: webhookSecret,
              insecure_ssl: "0"
            }
          },
          {
            headers: {
              Authorization: `Bearer ${githubToken.trim()}`,
              Accept: "application/vnd.github.v3+json"
            }
          }
        );
        webhookId = hookRes.data.id.toString();
      } catch (err) {
        console.warn("[projects] Failed to register GitHub webhook:", err.response?.data?.message || err.message);
        // We continue anyway so local testing with test scripts still works.
      }
    }

    const insert = await pool.query(
      "INSERT INTO projects (user_id, name, repo_url, language, framework, database_tech, github_token, is_private, webhook_id, webhook_secret) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
      [req.user.id, name, repoUrl, language, framework, databaseTech, isUsableGithubToken(githubToken) ? githubToken.trim() : null, isPrivateRepo, webhookId, webhookSecret]
    );

    return res.status(201).json({
      success: true,
      project: {
        ...insert.rows[0],
        projectName: insert.rows[0].name,
        repositoryUrl: insert.rows[0].repo_url,
        stack: insert.rows[0].language,
        description,
      },
      stack: { language, framework, database: databaseTech },
    });
  } catch (error) {
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

router.get("/", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, repo_url, language, framework, database_tech, target_url, webhook_secret, created_at FROM projects WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    const projects = await Promise.all(
      result.rows.map(async (project) => ({
        ...project,
        latestScan: await getLatestScanSummary(project.id),
      }))
    );
    return res.json({ projects });
  } catch (error) {
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

router.get("/:id", auth, async (req, res) => {
  try {
    const projectRes = await pool.query("SELECT * FROM projects WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    if (!projectRes.rows.length) return res.status(404).json({ error: "Project not found" });
    const latestScan = await getLatestScanSummary(req.params.id);
    return res.json({ project: projectRes.rows[0], latestScan });
  } catch (error) {
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

router.get("/:id/scans", auth, async (req, res) => {
  try {
    const exists = await pool.query("SELECT id FROM projects WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    if (!exists.rows.length) return res.status(404).json({ error: "Project not found" });

    const scans = await pool.query(
      "SELECT id, scan_type, status, total_issues, critical, high, medium, low, started_at, completed_at FROM scan_history WHERE project_id = $1 ORDER BY started_at DESC LIMIT 20",
      [req.params.id]
    );
    return res.json({ scans: scans.rows });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch scan history" });
  }
});

router.get("/:id/pipelines", auth, async (req, res) => {
  try {
    const exists = await pool.query("SELECT id FROM projects WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    if (!exists.rows.length) return res.status(404).json({ error: "Project not found" });

    const pipelines = await pool.query(
      "SELECT * FROM pipeline_executions WHERE project_id = $1 ORDER BY started_at DESC LIMIT 20",
      [req.params.id]
    );
    return res.json({ pipelines: pipelines.rows });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch pipeline history" });
  }
});

router.delete("/:id", auth, async (req, res) => {
  const projectId = Number.parseInt(String(req.params.id ?? "").trim(), 10);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: "Invalid project id" });
  }

  const client = await pool.connect();
  try {
    const exists = await client.query(
      "SELECT id FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!exists.rows.length) {
      return res.status(404).json({ error: "Project not found" });
    }

    await client.query("BEGIN");
    await client.query("DELETE FROM sbom_components WHERE project_id = $1", [projectId]);
    await client.query("DELETE FROM dependency_scans WHERE project_id = $1", [projectId]);
    await client.query("DELETE FROM scan_results WHERE project_id = $1", [projectId]);
    await client.query("DELETE FROM scan_history WHERE project_id = $1", [projectId]);
    await client.query("DELETE FROM iac_findings WHERE project_id = $1", [projectId]);
    await client.query("DELETE FROM iac_scans WHERE project_id = $1", [projectId]);
    await client.query("DELETE FROM dast_findings WHERE project_id = $1", [projectId]);
    await client.query("DELETE FROM dast_scans WHERE project_id = $1", [projectId]);
    await client.query("DELETE FROM pipeline_executions WHERE project_id = $1", [projectId]);
    const deleted = await client.query(
      "DELETE FROM projects WHERE id = $1 AND user_id = $2 RETURNING id",
      [projectId, req.user.id]
    );
    await client.query("COMMIT");

    if (!deleted.rows.length) {
      return res.status(404).json({ error: "Project not found" });
    }
    return res.json({ success: true, message: "Project deleted successfully" });
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {
      /* ignore */
    }
    console.error("[projects DELETE]", error.code || "", error.message);
    if (error.code === "23503") {
      return res.status(409).json({
        error:
          "Could not delete project because related rows still reference it. Run DB migrations so project FKs use ON DELETE CASCADE, or retry.",
      });
    }
    return res.status(500).json({ error: error.message || "Server error. Please try again." });
  } finally {
    client.release();
  }
});

module.exports = router;
