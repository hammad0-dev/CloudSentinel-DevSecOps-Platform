const express = require("express");
const crypto = require("crypto");
const pool = require("../db");
const { runPipeline } = require("../services/orchestrator");

const router = express.Router();

function normalizeRepositoryIdentity(value) {
  if (!value || typeof value !== "string") return null;
  const trimmed = value.trim();
  const fullNameMatch = trimmed.match(/^([^/\s]+)\/([^/\s]+?)(?:\.git)?$/);
  if (fullNameMatch) {
    return (fullNameMatch[1] + "/" + fullNameMatch[2]).toLowerCase();
  }

  try {
    const url = new URL(trimmed);
    if (url.hostname.toLowerCase() === "github.com") {
      const parts = url.pathname.replace(/^\/+|\/+$/g, "").split("/");
      if (parts.length === 2 && parts[0] && parts[1]) {
        return (parts[0] + "/" + parts[1].replace(/\.git$/i, "")).toLowerCase();
      }
    }
    if (url.hostname.toLowerCase() === "api.github.com") {
      const parts = url.pathname.replace(/^\/+|\/+$/g, "").split("/");
      if (parts.length === 3 && parts[0] === "repos" && parts[1] && parts[2]) {
        return (parts[1] + "/" + parts[2]).toLowerCase();
      }
    }
  } catch {
    return null;
  }
  return null;
}

function payloadRepositoryIdentity(body) {
  return normalizeRepositoryIdentity(
    body?.repository?.full_name ||
    body?.repository?.html_url ||
    body?.repository?.url
  );
}

function verifySignature(rawBody, signature, secret) {
  if (!rawBody || !signature || !secret) return false;
  if (!/^sha256=[a-f0-9]{64}$/i.test(signature)) return false;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest();
  const supplied = Buffer.from(signature.slice(7), "hex");
  return supplied.length === expected.length &&
    crypto.timingSafeEqual(supplied, expected);
}

router.post("/github", async (req, res) => {
  try {
    const event = req.headers["x-github-event"];
    const signature = req.headers["x-hub-signature-256"];

    if (!signature) {
      return res.status(401).json({ error: "Missing signature" });
    }
    if (!Buffer.isBuffer(req.rawBody)) {
      return res.status(400).json({ error: "Raw webhook body unavailable" });
    }

    const repositoryIdentity = payloadRepositoryIdentity(req.body);
    if (!repositoryIdentity) {
      return res.status(400).json({ error: "Missing or invalid repository identity in payload" });
    }

    const projectRes = await pool.query(
      "SELECT id, user_id, repo_url, webhook_secret " +
      "FROM projects " +
      "WHERE LOWER(REGEXP_REPLACE(TRIM(TRAILING '/' FROM repo_url), '\\.git$', '', 'i')) = $1",
      ["https://github.com/" + repositoryIdentity]
    );

    if (projectRes.rows.length === 0) {
      return res.status(404).json({ error: "Project not found for this repository" });
    }

    const matchingProjects = projectRes.rows.filter((candidate) =>
      normalizeRepositoryIdentity(candidate.repo_url) === repositoryIdentity &&
      verifySignature(req.rawBody, signature, candidate.webhook_secret)
    );

    if (matchingProjects.length === 0) {
      console.warn("[webhook] Signature mismatch for repository " + repositoryIdentity);
      return res.status(401).json({ error: "Invalid signature" });
    }
    if (matchingProjects.length > 1) {
      console.error("[webhook] Ambiguous authenticated webhook for repository " + repositoryIdentity);
      return res.status(409).json({ error: "Ambiguous webhook configuration" });
    }

    const project = matchingProjects[0];

    if (event === "ping") {
      return res.status(200).json({ success: true, message: "Pong" });
    }
    if (event !== "push") {
      return res.status(200).json({ success: true, message: "Ignored non-push event" });
    }

    if(require('../services/pipelineProvenance').enabled()){
      try{
        const recovery=require('../services/provenanceRecovery');
        if(!recovery.ready())return res.status(503).json({error:'Provenance dispatch recovery is not ready; pipeline not created'});
        const result=await require('../services/pipelineProvenance').registerPush(pool,project,req.body,req.headers['x-github-delivery'],req.rawBody);
        res.status(202).json({success:true,...result,message:result.duplicate?'Delivery already accepted':'Pipeline triggered'});
        recovery.wake(result.executionId,{projectId:project.id,userId:project.user_id,repository:require('../services/pipelineProvenance').canonical(project.repo_url),repositoryId:req.body.repository.id,branch:req.body.ref.slice('refs/heads/'.length),commit:req.body.after});
        return;
      }catch(e){return res.status(e.safe?e.status:503).json({error:e.safe?e.message:'Push provenance unavailable; pipeline not started'});}
    }

    const activeRes = await pool.query(
      "SELECT id FROM pipeline_executions WHERE project_id = $1 AND status IN ('TRIGGERED', 'RUNNING') LIMIT 1",
      [project.id]
    );

    if (activeRes.rows.length > 0) {
      console.warn("[webhook] Pipeline already running for project " + project.id + ". Rejecting new trigger.");
      return res.status(409).json({ error: "Pipeline is already active for this project." });
    }

    const execRes = await pool.query(
      "INSERT INTO pipeline_executions (project_id, status, triggered_by) VALUES ($1, 'TRIGGERED', 'webhook') RETURNING id",
      [project.id]
    );
    const executionId = execRes.rows[0].id;

    res.status(202).json({ success: true, executionId, message: "Pipeline triggered" });
    runPipeline(executionId, project.id, project.user_id);
  } catch (err) {
    console.error("[webhook] Error:", err.message);
    return res.status(500).json({ error: "Internal webhook error" });
  }
});

module.exports = router;
