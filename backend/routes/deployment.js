/**
 * backend/routes/deployment.js
 * REST endpoints for deployment history and status.
 */
const express = require("express");
const pool = require("../db");
const auth = require("../middleware/auth");

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

    const result = await pool.query(
      `SELECT id, status, deployed_at, staging_url, dockerfile_source,
              manifest_source, app_name, image_tag, failure_reason
       FROM deployment_history WHERE project_id = $1 ORDER BY deployed_at DESC LIMIT 10`,
      [projectId]
    );
    return res.json({ deployments: result.rows });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
