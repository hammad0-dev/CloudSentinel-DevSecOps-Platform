/**
 * backend/routes/deployment.js
 * REST endpoints for deployment history and status.
 */
const express = require("express");
const pool = require("../db");
const auth = require("../middleware/auth");
const { getProjectNamespace } = require("../services/kubernetesNamespace");

const router = express.Router();

// GET /api/deployment/:projectId/history
router.get("/:projectId/history", auth, async (req, res) => {
  try {
    const projectId = parseInt(req.params.projectId);
    const ownerCheck = await pool.query(
      "SELECT id FROM projects WHERE id = $1 AND user_id = $2",
      [projectId, req.user.id]
    );
    if (!ownerCheck.rows.length) return res.status(404).json({ error: "Project not found" });

    const requestedExecutionId = req.query.pipelineExecutionId;
    const params = [projectId];
    let where = "project_id = $1";
    if (requestedExecutionId !== undefined) {
      const executionId = Number(requestedExecutionId);
      if (!Number.isInteger(executionId) || executionId <= 0) {
        return res.status(400).json({ error: "pipelineExecutionId must be a positive integer" });
      }
      const executionCheck = await pool.query(
        "SELECT id FROM pipeline_executions WHERE id = $1 AND project_id = $2",
        [executionId, projectId]
      );
      if (!executionCheck.rows.length) return res.status(404).json({ error: "Pipeline execution not found for this project" });
      params.push(executionId);
      where += " AND pipeline_execution_id = $2";
    }
    const result = await pool.query(
      `SELECT id, pipeline_execution_id, deployment_attempt, status, deployed_at, staging_url,
              dockerfile_source, manifest_source, app_name, image_tag, failure_reason
       FROM deployment_history WHERE ${where} ORDER BY deployed_at DESC LIMIT 10`,
      params
    );
    return res.json({ deployments: result.rows.map(row => ({ ...row, namespace: getProjectNamespace(projectId) })) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
