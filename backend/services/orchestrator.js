const axios = require("axios");
const jwt = require("jsonwebtoken");
const pool = require("../db");
const { deployProject } = require("./deployment");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runStage(executionId, projectId, userId, stageName, endpoint) {
  const token = jwt.sign({ id: userId, pipelineExecutionId: executionId, pipelineOrchestrator: true }, process.env.JWT_SECRET, { expiresIn: "1h" });
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

async function runDeployStage(executionId, projectId, userId) {
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const result = await deployProject(projectId, userId, { executionId, attempt });
      return result;
    } catch (err) {
      console.error(`[orchestrator] Deploy attempt ${attempt} failed for project ${projectId}:`, err.message);
      if (err?.code === "IMAGE_SECURITY_GATE_BLOCKED" || err?.nonRetryable === true) {
        throw err;
      }
      if (attempt === 1) {
        console.log(`[orchestrator] Retrying Deploy in 60s...`);
        await sleep(60000);
      } else {
        throw new Error(`Deploy stage failed after 2 attempts: ${err.message}`);
      }
    }
  }
}

async function checkCriticalFindings(projectId, executionId, stageName) {
  const table = { SAST: "scan_history", Dependency: "dependency_scans", IaC: "iac_scans" }[stageName];
  if (!table) return { evidenceFound: true, hasCritical: false, evidenceConsistent: true };
  if (stageName === "SAST") {
    const result = await pool.query(
      `SELECT sh.critical, sh.high, sh.medium, sh.low, sh.total_issues,
        COUNT(sr.id)::int AS persisted_total,
        COUNT(DISTINCT (sr.rule, sr.severity, sr.message, sr.file_path, sr.line_number))::int AS distinct_total,
        COUNT(*) FILTER (WHERE UPPER(sr.severity) = 'CRITICAL')::int AS persisted_critical,
        COUNT(*) FILTER (WHERE UPPER(sr.severity) IN ('MAJOR', 'HIGH'))::int AS persisted_high,
        COUNT(*) FILTER (WHERE UPPER(sr.severity) IN ('MINOR', 'MEDIUM', 'LOW'))::int AS persisted_medium,
        COUNT(*) FILTER (WHERE UPPER(sr.severity) NOT IN ('CRITICAL', 'MAJOR', 'HIGH', 'MINOR', 'MEDIUM', 'LOW'))::int AS persisted_low
       FROM scan_history sh
       LEFT JOIN scan_results sr ON sr.project_id = sh.project_id AND sr.scan_history_id = sh.id
       WHERE sh.project_id = $1 AND sh.pipeline_execution_id = $2
         AND sh.status = 'COMPLETED' AND sh.sast_details_linked = TRUE
       GROUP BY sh.id ORDER BY sh.id DESC LIMIT 1`,
      [projectId, executionId]
    );
    if (!result.rows.length) return { evidenceFound: false, hasCritical: true, evidenceConsistent: false };
    const row = result.rows[0];
    const expected = [row.total_issues, row.critical, row.high, row.medium, row.low].map(Number);
    const actual = [row.persisted_total, row.persisted_critical, row.persisted_high, row.persisted_medium, row.persisted_low].map(Number);
    const evidenceConsistent = expected.every(Number.isFinite) && actual.every(Number.isFinite) &&
      expected.every((value, index) => value === actual[index]) && actual[0] === Number(row.distinct_total);
    return { evidenceFound: true, hasCritical: Number(row.critical || 0) > 0, evidenceConsistent };
  }
  const result = await pool.query(`SELECT critical FROM ${table} WHERE project_id = $1 AND pipeline_execution_id = $2 AND status = 'COMPLETED' ORDER BY id DESC LIMIT 1`, [projectId, executionId]);
  if (!result.rows.length) return { evidenceFound: false, hasCritical: true, evidenceConsistent: false };
  return { evidenceFound: true, hasCritical: Number(result.rows[0].critical || 0) > 0, evidenceConsistent: true };
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
      const gate = await checkCriticalFindings(projectId, executionId, stage.name);
      if (!gate.evidenceFound || !gate.evidenceConsistent || gate.hasCritical) {
        await pool.query(
          "UPDATE pipeline_executions SET status = 'STAGE_FAILED', failure_reason = $1, completed_at = NOW() WHERE id = $2",
          [!gate.evidenceFound || !gate.evidenceConsistent ? `Missing or inconsistent completed ${stage.name} evidence for this execution. Pipeline stopped.` : `CRITICAL vulnerability found in ${stage.name} stage. Pipeline stopped.`, executionId]
        );
        return;
      }
    }

    // Phase 2: Deploy to Kubernetes staging
    let deployResult;
    try {
      console.log(`[orchestrator] Starting Deploy stage for project ${projectId}`);
      deployResult = await runDeployStage(executionId, projectId, userId);
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
    const targetUrl = deployResult?.stagingUrl;

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

    // Explicitly opt-in, execution-bound Active DAST. Never retries or falls
    // back to the staging URL/Project 17 when authorization is unavailable.
    if (process.env.DAST_ACTIVE_ENABLED === 'true') {
      const active = await require('./module2ActiveDast').execute({pool,projectId,executionId,userId});
      await pool.query("INSERT INTO active_dast_executions (project_id,pipeline_execution_id,status,duration_ms,result) VALUES ($1,$2,$3,$4,$5)",[projectId,executionId,active.status,active.durationMs,JSON.stringify(active)]);
      stagesCompleted.push('Active DAST');
      await pool.query("UPDATE pipeline_executions SET stages_completed=$1 WHERE id=$2",[stagesCompleted.join(', '),executionId]);
      if (!['COMPLETED_WITH_FINDINGS','COMPLETED_NO_FINDINGS'].includes(active.status)) {
        await pool.query("UPDATE pipeline_executions SET status='STAGE_FAILED', failure_reason=$1, completed_at=NOW() WHERE id=$2",[`Active DAST ${active.status}: ${active.reason||'cleanup failed'}`,executionId]);
        return;
      }
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

module.exports = { runPipeline, checkCriticalFindings };
