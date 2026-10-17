const axios = require("axios");
const jwt = require("jsonwebtoken");
const pool = require("../db");
const { deployProject } = require("./deployment");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runStage(executionId, projectId, userId, stageName, endpoint) {
  const commissioning = !!require('./activeDastCommissioning').selection({projectId,executionId,userId});
  const maxAttempts = commissioning ? 1 : 2;
  const token = jwt.sign({ id: userId, pipelineExecutionId: executionId, pipelineOrchestrator: true,
    ...(commissioning ? {commissioningStaticStage:true} : {}) }, process.env.JWT_SECRET, { expiresIn: "1h" });
  const headers = { Authorization: `Bearer ${token}` };

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await axios.post(
        `http://127.0.0.1:${process.env.PORT || 3000}/api/${endpoint}/scan/${projectId}`,
        {},
        { headers, timeout: 1_800_000 }
      );
      return res.data.summary || res.data;
    } catch (err) {
      const status = err.response?.status;
      const detail = require("./staticStageFailure").responseError(err);
      if (status === 409) throw new Error(`Stage ${stageName} failed: scan already running.`);
      console.error(`[orchestrator] Stage ${stageName} attempt ${attempt} failed for project ${projectId}:`, detail);
      if (attempt < maxAttempts) {
        console.log(`[orchestrator] Retrying ${stageName} in 60s...`);
        await sleep(60000);
      } else {
        throw new Error(`Stage ${stageName} failed after ${maxAttempts} attempts: ${detail}`);
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
        COUNT(sr.id) FILTER (WHERE sr.issue_type = 'VULNERABILITY' AND UPPER(sr.severity) IN ('CRITICAL','BLOCKER'))::int AS security_critical,
        COUNT(sr.id) FILTER (WHERE sr.issue_type = 'VULNERABILITY' AND UPPER(sr.severity) IN ('MAJOR','HIGH'))::int AS security_high,
        COUNT(sr.id) FILTER (WHERE sr.issue_type = 'SECURITY_HOTSPOT' AND sr.hotspot_review NOT IN ('SAFE','FIXED'))::int AS hotspots_pending,
        COUNT(sr.id) FILTER (WHERE sr.issue_type IS NULL OR sr.issue_type NOT IN ('CODE_SMELL','BUG','VULNERABILITY','SECURITY_HOTSPOT'))::int AS unknown_types,
        COUNT(sr.id)::int AS persisted_total,
        COUNT(DISTINCT (sr.rule, sr.severity, sr.message, sr.file_path, sr.line_number)) FILTER (WHERE sr.id IS NOT NULL)::int AS distinct_total,
        COUNT(sr.id) FILTER (WHERE UPPER(sr.severity) IN ('CRITICAL','BLOCKER'))::int AS persisted_critical,
        COUNT(sr.id) FILTER (WHERE UPPER(sr.severity) IN ('MAJOR', 'HIGH'))::int AS persisted_high,
        COUNT(sr.id) FILTER (WHERE UPPER(sr.severity) IN ('MINOR', 'MEDIUM', 'LOW'))::int AS persisted_medium,
        COUNT(sr.id) FILTER (WHERE UPPER(sr.severity) NOT IN ('CRITICAL', 'BLOCKER', 'MAJOR', 'HIGH', 'MINOR', 'MEDIUM', 'LOW'))::int AS persisted_low
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
    const counts = [row.total_issues,row.critical,row.high,row.medium,row.low,
      row.persisted_total,row.persisted_critical,row.persisted_high,row.persisted_medium,row.persisted_low,row.distinct_total];
    const evidenceConsistent = counts.every(value => value !== null && value !== undefined &&
      Number.isSafeInteger(Number(value)) && Number(value) >= 0) &&
      expected.every((value, index) => value === actual[index]) && actual[0] === Number(row.distinct_total) &&
      expected[0] === expected.slice(1).reduce((sum,value)=>sum+value,0);
    const security=require('./sastClassification').gate(row);
    return {evidenceFound:true,...security,evidenceConsistent:evidenceConsistent&&security.classificationVerified};
  }
  const result = await pool.query(`SELECT critical FROM ${table} WHERE project_id = $1 AND pipeline_execution_id = $2 AND status = 'COMPLETED' ORDER BY id DESC LIMIT 1`, [projectId, executionId]);
  if (!result.rows.length) return { evidenceFound: false, hasCritical: true, evidenceConsistent: false };
  return { evidenceFound: true, hasCritical: Number(result.rows[0].critical || 0) > 0, evidenceConsistent: true };
}
async function runPipeline(executionId, projectId, userId) {
  let awaitingActiveAuthorization=false;
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
      if (!gate.evidenceFound || !gate.evidenceConsistent || gate.hasCritical || gate.hasHigh || gate.requiresReview) {
        await pool.query(
          "UPDATE pipeline_executions SET status = 'STAGE_FAILED', failure_reason = $1, completed_at = NOW() WHERE id = $2",
          [!gate.evidenceFound || !gate.evidenceConsistent ? `Missing or inconsistent completed ${stage.name} evidence for this execution. Pipeline stopped.` : gate.requiresReview ? 'SAST security review required: unreviewed hotspot or unclassified finding. Pipeline stopped.' : `${gate.hasCritical ? 'CRITICAL' : 'HIGH'} security vulnerability found in ${stage.name} stage. Pipeline stopped.`, executionId]
        );
        return;
      }
    }

    // Phase 2: Deploy to Kubernetes staging
    let deployResult;
    try {
      console.log(`[orchestrator] Starting Deploy stage for project ${projectId}`);
      deployResult = require('./activeDastCommissioning').selection({projectId,executionId,userId})
        ? await require('./commissioningFixtureStage').prepare(pool,{projectId,executionId,userId})
        : await runDeployStage(executionId, projectId, userId);
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
      if(!deployResult.fixtureOnly)await runStage(executionId, projectId, userId, "DAST", "dast");
      else await require('./commissioningFixtureStage').verify(pool,{projectId,executionId,userId});
      stagesCompleted.push("DAST");
      await pool.query(
        "UPDATE pipeline_executions SET stages_completed = $1 WHERE id = $2",
        [stagesCompleted.join(", "), executionId]
      );
    } else {
      console.warn(`[orchestrator] Skipping DAST — no valid staging URL for project ${projectId}`);
    }

    if(deployResult?.fixtureOnly){
      await require('./commissioningPhases').pause(pool,{projectId,executionId,userId});
      awaitingActiveAuthorization=true;
      return; // Persisted pause: no waitForGrant, consumption or Active job.
    }
    // Explicitly opt-in, execution-bound Active DAST. Never retries or falls
    // back to the staging URL/Project 17 when authorization is unavailable.
    if (process.env.DAST_ACTIVE_ENABLED === 'true') {
      const active = stagesCompleted.includes('DAST')
        ? await require('./module2ActiveDast').execute({pool,projectId,executionId,userId})
        : {status:'BLOCKED',scanMode:'ACTIVE',durationMs:0,reason:'ACTIVE_STAGING_DAST_GATE_BLOCKED'};
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
  } finally {
    const context={projectId,executionId,userId};
    if(!awaitingActiveAuthorization&&(require('./commissioningFixtureStage').has(context)||require('./activeOperatorEnrollment').scopeFor(context,{includeExpired:true}))){
      let cleanupFailed=false;
      try{const cleanup=await require('./activeRuntimeRegistry').cancelPending(context);if(!cleanup.cleaned)throw Error('Commissioning cleanup incomplete');}
      catch(_){cleanupFailed=true;await pool.query("UPDATE pipeline_executions SET status='STAGE_FAILED',failure_reason='Active DAST CLEANUP_FAILED',completed_at=NOW() WHERE id=$1",[executionId]);}
      require('./commissioningFixtureStage').release(context);
      if(process.env.DAST_COMMISSIONING_SETUP_ENABLED==='true')await require('./commissioningPhases').failSetup(pool,context,cleanupFailed);
    }
  }
}
async function resumeActive(executionId,projectId,userId){
 const context={projectId,executionId,userId};await require('./commissioningPhases').assertActive(pool,context);
 const result=await require('./module2ActiveDast').execute({pool,...context});
 try{
  // Late completion may be recorded as a failure, never as authorized success.
  require('./commissioningBudget').fenceResult(result);
  await pool.query('INSERT INTO active_dast_executions (project_id,pipeline_execution_id,status,duration_ms,result) VALUES ($1,$2,$3,$4,$5)',[projectId,executionId,result.status,result.durationMs,JSON.stringify(result)]);
  if(require('./commissioningBudget').fenceResult(result))await pool.query('UPDATE active_dast_executions SET status=$3,result=$4 WHERE project_id=$1 AND pipeline_execution_id=$2',[projectId,executionId,result.status,JSON.stringify(result)]);
  await require('./commissioningPhases').finish(pool,context,result);
  await pool.query("UPDATE pipeline_executions SET status=$2,completed_at=NOW(),failure_reason=$3 WHERE id=$1 AND project_id=$4 AND status='RUNNING'",[executionId,result.status.startsWith('COMPLETED')?'COMPLETED':'STAGE_FAILED',result.reason||null,projectId]);
 }catch(error){await require('./commissioningPhases').finish(pool,context,{status:'FAILED',cleanup:result.cleanup});throw error;}
 return result;
}

module.exports = { runPipeline, resumeActive, checkCriticalFindings };
