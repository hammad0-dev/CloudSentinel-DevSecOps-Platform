"use strict";

const express = require("express");
const pool = require("../db");
const auth = require("../middleware/auth");
const { resolvePipelineExecutionId } = require("../services/pipelineExecutionContext");
const { runBaselineScan } = require("../services/dastBaselineScanner");

const router = express.Router();
router.post('/active/:projectId/executions/:executionId/grants',auth,async(req,res)=>{
  if(req.user.pipelineOrchestrator===true)return res.status(403).json({error:'Operator authentication required'});
  const projectId=Number(req.params.projectId),executionId=Number(req.params.executionId),userId=Number(req.user.id);
  try {
    const result=await require('../services/activeDastGrants').issue(pool,{projectId,executionId,userId},req.body?.targetId);
    return res.status(201).json(result);
  }catch(error){return res.status(error.status||503).json({error:/^[A-Z_]{1,64}$/.test(error.code||'')?error.code:'ACTIVE_GRANT_UNAVAILABLE'});}
});
router.get('/active/:projectId/executions/:executionId',auth,async(req,res)=>{
  const projectId=positiveId(req.params.projectId),executionId=positiveId(req.params.executionId);
  if(!projectId||!executionId)return res.status(400).json({error:'Invalid execution identity'});
  try {
    const owned=await pool.query('SELECT id FROM projects WHERE id=$1 AND user_id=$2',[projectId,req.user.id]);
    if(!owned.rows.length)return res.status(404).json({error:'Project not found'});
    const result=await pool.query('SELECT status,duration_ms,result,created_at FROM active_dast_executions WHERE project_id=$1 AND pipeline_execution_id=$2',[projectId,executionId]);
    return res.json({active:result.rows[0]||null});
  }catch(error){return res.status(503).json({error:'Active DAST execution reporting is unavailable'});}
});
const scanFields = "id,status,target_url,total_findings,high,medium,low,informational,started_at,completed_at,scan_mode,scan_group_id,policy_name,policy_version,failure_reason";
function positiveId(value) { const id = Number.parseInt(String(value ?? "").trim(), 10); return Number.isInteger(id) && id > 0 ? id : null; }
function validTarget(value) { try { const parsed = new URL(String(value || "").trim()); return ["http:", "https:"].includes(parsed.protocol); } catch (_) { return false; } }

router.patch("/target/:projectId", auth, async (req, res) => {
  try {
    const projectId = positiveId(req.params.projectId), targetUrl = String(req.body?.target_url || "").trim();
    if (!projectId) return res.status(400).json({ error: "Invalid project id" });
    if (!validTarget(targetUrl)) return res.status(400).json({ error: "target_url must be a valid HTTP(S) URL" });
    const updated = await pool.query("UPDATE projects SET target_url=$1 WHERE id=$2 AND user_id=$3 RETURNING id", [targetUrl, projectId, req.user.id]);
    if (!updated.rowCount) return res.status(404).json({ error: "Project not found" });
    return res.json({ success: true, target_url: targetUrl });
  } catch (_) { return res.status(500).json({ error: "Failed to save target URL" }); }
});

router.post("/scan/:projectId", auth, async (req, res) => {
  const projectId = positiveId(req.params.projectId);
  if (!projectId) return res.status(400).json({ error: "Invalid project id" });
  try {
    const project = await pool.query("SELECT id,target_url FROM projects WHERE id=$1 AND user_id=$2", [projectId, req.user.id]);
    if (!project.rows.length) return res.status(404).json({ error: "Project not found" });
    const executionId = await resolvePipelineExecutionId(pool, req.user, projectId);
    const targetUrl = project.rows[0].target_url?.trim();
    if (!targetUrl) return res.status(400).json({ error: "No DAST target URL configured for this project. Set one on the DAST results page first." });
    const result = await runBaselineScan({ pool, projectId, executionId, targetUrl, userId: req.user.id });
    return res.json({ success: true, ...result });
  } catch (error) {
    console.error(`[dast project=${projectId}]`, error.message);
    return res.status(error.status || 500).json({ error: error.message || "DAST scan failed" });
  }
});

router.get("/:projectId", auth, async (req, res) => {
  try {
    const projectId = positiveId(req.params.projectId);
    if (!projectId) return res.status(400).json({ error: "Invalid project id" });
    const project = await pool.query("SELECT id,target_url FROM projects WHERE id=$1 AND user_id=$2", [projectId, req.user.id]);
    if (!project.rows.length) return res.status(404).json({ error: "Project not found" });
    const scanId = req.query.scanId === undefined ? null : positiveId(req.query.scanId);
    if (req.query.scanId !== undefined && !scanId) return res.status(400).json({ error: "Invalid scan id" });
    const selected = await pool.query(scanId ? `SELECT ${scanFields} FROM dast_scans WHERE project_id = $1 AND id = $2 LIMIT 1` : `SELECT ${scanFields} FROM dast_scans WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1`, scanId ? [projectId, scanId] : [projectId]);
    const latestScan = selected.rows[0] || null;
    const history = await pool.query(`SELECT ${scanFields} FROM dast_scans WHERE project_id = $1 ORDER BY started_at DESC`, [projectId]);
    const findings = latestScan ? await pool.query("SELECT id,alert,attack_type,severity,endpoint,method,param,request_payload,response_details,cwe_id,solution,created_at,finding_fingerprint FROM dast_findings WHERE project_id = $1 AND scan_id = $2 ORDER BY CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 WHEN 'INFORMATIONAL' THEN 4 ELSE 5 END,alert", [projectId, latestScan.id]) : { rows: [] };
    return res.json({ latestScan, findings: findings.rows, history: history.rows, summary: { high: latestScan?.high ?? 0, medium: latestScan?.medium ?? 0, low: latestScan?.low ?? 0, informational: latestScan?.informational ?? 0, total: latestScan?.total_findings ?? 0 }, target_url: project.rows[0].target_url || null });
  } catch (error) { console.error("[dast] GET", error.message); return res.status(500).json({ error: "Server error. Please try again." }); }
});

module.exports = router;
