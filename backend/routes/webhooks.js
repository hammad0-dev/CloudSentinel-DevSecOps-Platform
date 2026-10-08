const express = require("express");
const crypto = require("crypto");
const pool = require("../db");
const { runPipeline } = require("../services/orchestrator");

const router = express.Router();

function verifySignature(req, secret) {
  const signature = req.headers["x-hub-signature-256"];
  if (!signature) return false;

  // GitHub sends the payload raw. We must use the raw body for HMAC.
  // We'll assume the body-parser raw middleware is used or we can serialize it.
  // Since express.json() is already parsing, recreating it exactly is risky if whitespace changes.
  // Standard approach: use a custom verify function in express.json() to save rawBody, 
  // but for now we'll stringify. If it fails due to formatting, we'll need rawBody.
  // Let's use the req.rawBody if available, else fallback to stringify.
  const payload = req.rawBody || JSON.stringify(req.body);
  
  const hmac = crypto.createHmac("sha256", secret);
  const digest = "sha256=" + hmac.update(payload).digest("hex");
  
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
  } catch (e) {
    return false;
  }
}

router.post("/github", async (req, res) => {
  try {
    const event = req.headers["x-github-event"];
    if (event === "ping") {
      return res.status(200).json({ success: true, message: "Pong" });
    }
    if (event !== "push") {
      return res.status(200).json({ success: true, message: "Ignored non-push event" });
    }

    const repoUrl = req.body.repository?.html_url || req.body.repository?.url;
    if (!repoUrl) {
      return res.status(400).json({ error: "Missing repository URL in payload" });
    }

    // Find the project based on the repo_url
    // GitHub sends https://github.com/owner/repo. We can match using ILIKE or a simple parse.
    const projectRes = await pool.query(
      "SELECT id, user_id, webhook_secret FROM projects WHERE repo_url ILIKE $1 OR repo_url ILIKE $2",
      [`${repoUrl}%`, `${repoUrl}.git`]
    );

    if (projectRes.rows.length === 0) {
      return res.status(404).json({ error: "Project not found for this repository" });
    }

    const project = projectRes.rows[0];

    // Verify HMAC signature BEFORE trusting the payload
    if (!project.webhook_secret) {
      return res.status(401).json({ error: "Webhook secret not configured for this project" });
    }

    if (!verifySignature(req, project.webhook_secret)) {
      console.warn(`[webhook] Signature mismatch for project ${project.id}`);
      return res.status(401).json({ error: "Invalid signature" });
    }

    // Concurrency control: check if a pipeline is already running or triggered
    const activeRes = await pool.query(
      "SELECT id FROM pipeline_executions WHERE project_id = $1 AND status IN ('TRIGGERED', 'RUNNING') LIMIT 1",
      [project.id]
    );

    if (activeRes.rows.length > 0) {
      console.warn(`[webhook] Pipeline already running for project ${project.id}. Rejecting new trigger.`);
      return res.status(409).json({ error: "Pipeline is already active for this project." });
    }

    // Insert new execution
    const execRes = await pool.query(
      "INSERT INTO pipeline_executions (project_id, status, triggered_by) VALUES ($1, 'TRIGGERED', 'webhook') RETURNING id",
      [project.id]
    );
    const executionId = execRes.rows[0].id;

    // Acknowledge the webhook quickly
    res.status(202).json({ success: true, executionId, message: "Pipeline triggered" });

    // Kick off orchestration async
    runPipeline(executionId, project.id, project.user_id);

  } catch (err) {
    console.error("[webhook] Error:", err.message);
    return res.status(500).json({ error: "Internal webhook error" });
  }
});

module.exports = router;
