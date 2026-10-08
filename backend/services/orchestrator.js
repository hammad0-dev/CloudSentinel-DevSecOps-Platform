const axios = require("axios");
const jwt = require("jsonwebtoken");
const pool = require("../db");
const { deployProject } = require("./deployment");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runStage(executionId, projectId, userId, stageName, endpoint) {
  const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: "1h" });
  const headers = { Authorization: `Bearer ${token}` };

  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const res = await axios.post(
        `http://127.0.0.1:${process.env.PORT || 3000}/api/${endpoint}/scan/${projectId}`,
        {},
        { headers, timeout: 1_800_000 }
      );
      return res.data.summary || res.data;
    } catch (err) {
      const status = err.response?.status;
      if (status === 409) throw new Error(`Stage ${stageName} failed: scan already running.`);
      console.error(`[orchestrator] Stage ${stageName} attempt ${attempt} failed for project ${projectId}:`, err.message);
      if (attempt === 1) {
        console.log(`[orchestrator] Retrying ${stageName} in 60s...`);
        await sleep(60000);
      } else {
        throw new Error(`Stage ${stageName} failed after 2 attempts: ${err.message}`);
      }
    }
  }
}

async function runDeployStage(executionId, projectId) {
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const result = await deployProject(projectId);
      return result;
    } catch (err) {
      console.error(`[orchestrator] Deploy attempt ${attempt} failed for project ${projectId}:`, err.message);
      if (attempt === 1) {
        console.log(`[orchestrator] Retrying Deploy in 60s...`);
        await sleep(60000);
      } else {
        throw new Error(`Deploy stage failed after 2 attempts: ${err.message}`);
      }
    }
  }
}

async function checkCriticalFindings(projectId, stageName) {
  let criticalCount = 0;
  if (stageName === "SAST") {
    const res = await pool.query(
      "SELECT critical FROM scan_history WHERE project_id = $1 AND scan_type = 'SAST' ORDER BY started_at DESC LIMIT 1",
      [projectId]
    );
    criticalCount = res.rows[0]?.critical || 0;
  } else if (stageName === "Dependency") {
    const res = await pool.query(
      "SELECT critical FROM dependency_scans WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1",
      [projectId]
    );
    criticalCount = res.rows[0]?.critical || 0;
  } else if (stageName === "IaC") {
    const res = await pool.query(
      "SELECT critical FROM iac_scans WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1",
      [projectId]
    );
    criticalCount = res.rows[0]?.critical || 0;
  }
  return criticalCount > 0;
}

async function runPipeline(executionId, projectId, userId) {
  try {
    await pool.query("UPDATE pipeline_executions SET status = 'RUNNING' WHERE id = $1", [executionId]);

    const stagesCompleted = [];

    // Phase 1: Static analysis (fail-fast on CRITICAL)
    const staticStages = [
      { name: "SAST", endpoint: "sast" },
      { name: "Dependency", endpoint: "dependencies" },
      { name: "IaC", endpoint: "iac" },
    ];

    for (const stage of staticStages) {
      await runStage(executionId, projectId, userId, stage.name, stage.endpoint);
      stagesCompleted.push(stage.name);
      await pool.query(
        "UPDATE pipeline_executions SET stages_completed = $1 WHERE id = $2",
        [stagesCompleted.join(", "), executionId]
      );
      const hasCritical = await checkCriticalFindings(projectId, stage.name);
      if (hasCritical) {
        await pool.query(
          "UPDATE pipeline_executions SET status = 'STAGE_FAILED', failure_reason = $1, completed_at = NOW() WHERE id = $2",
          [`CRITICAL vulnerability found in ${stage.name} stage. Pipeline stopped.`, executionId]
        );
        return;
      }
    }

    // Phase 2: Deploy to Kubernetes staging
    try {
      console.log(`[orchestrator] Starting Deploy stage for project ${projectId}`);
      const deployResult = await runDeployStage(executionId, projectId);
      stagesCompleted.push("Deploy");
      await pool.query(
        "UPDATE pipeline_executions SET stages_completed = $1 WHERE id = $2",
        [stagesCompleted.join(", "), executionId]
      );
      console.log(`[orchestrator] Deployed to staging: ${deployResult?.stagingUrl}`);
    } catch (deployErr) {
      await pool.query(
        "UPDATE pipeline_executions SET status = 'ERROR', failure_reason = $1, completed_at = NOW() WHERE id = $2",
        [`Deploy stage failed: ${deployErr.message}`, executionId]
      );
      return;
    }

    // Phase 3: DAST against live staging URL
    const projRes = await pool.query("SELECT target_url FROM projects WHERE id = $1", [projectId]);
    const targetUrl = projRes.rows[0]?.target_url;

    if (targetUrl && targetUrl.trim() !== "" && targetUrl !== "http://minikube-url-unavailable") {
      await runStage(executionId, projectId, userId, "DAST", "dast");
      stagesCompleted.push("DAST");
      await pool.query(
        "UPDATE pipeline_executions SET stages_completed = $1 WHERE id = $2",
        [stagesCompleted.join(", "), executionId]
      );
    } else {
      console.warn(`[orchestrator] Skipping DAST — no valid staging URL for project ${projectId}`);
    }

    await pool.query(
      "UPDATE pipeline_executions SET status = 'COMPLETED', completed_at = NOW() WHERE id = $1",
      [executionId]
    );

  } catch (error) {
    console.error(`[orchestrator] Pipeline ${executionId} error:`, error);
    await pool.query(
      "UPDATE pipeline_executions SET status = 'ERROR', failure_reason = $1, completed_at = NOW() WHERE id = $2",
      [error.message || "Unknown internal error", executionId]
    );
  }
}

module.exports = { runPipeline };
