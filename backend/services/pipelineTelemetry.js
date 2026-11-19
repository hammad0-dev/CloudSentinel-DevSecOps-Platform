// Module 11 FE-1/FE-3: wraps orchestrator functions to emit structured events and Prometheus metrics.
const { logEvent } = require("./securityLog");
const metrics = require("./metrics");

const FAILED = new Set(["FAILED", "STAGE_FAILED", "BLOCKED", "DEPLOY_FAILED"]);

function outcomeOf(status) {
  if (status === "COMPLETED" || String(status || "").startsWith("COMPLETED")) return "completed";
  if (FAILED.has(status) || /FAIL/.test(String(status || ""))) return "failed";
  return "other";
}

function instrumentStage(fn, stageArg = (args) => args[3]) {
  return async function instrumentedStage(...args) {
    const [executionId, projectId, userId] = args;
    const stage = stageArg(args);
    const started = Date.now();
    logEvent({ event: "pipeline_stage_started", projectId, userId, detail: { executionId, stage } });
    try {
      const result = await fn.apply(this, args);
      const durationMs = Date.now() - started;
      metrics.stageDuration.observe({ stage, outcome: "success" }, durationMs / 1000);
      logEvent({ event: "pipeline_stage_finished", projectId, userId, detail: { executionId, stage, durationMs } });
      if (stage === "Deploy") logEvent({ event: "deployment_result", projectId, userId, detail: { executionId, status: "SUCCESS", url: result?.stagingUrl || result?.url || null } });
      return result;
    } catch (err) {
      const durationMs = Date.now() - started;
      metrics.stageDuration.observe({ stage, outcome: "failure" }, durationMs / 1000);
      logEvent({ level: "error", event: "pipeline_stage_failed", projectId, userId, detail: { executionId, stage, durationMs, error: String(err?.message || err).slice(0, 500) } });
      if (stage === "Deploy") logEvent({ level: "error", event: "deployment_result", projectId, userId, detail: { executionId, status: "FAILED", error: String(err?.message || err).slice(0, 500) } });
      throw err;
    }
  };
}

function instrumentPipeline(fn, pool) {
  return async function instrumentedPipeline(...args) {
    const [executionId, projectId, userId] = args;
    const started = Date.now();
    metrics.pipelineRuns.inc({ status: "started" });
    logEvent({ event: "pipeline_started", projectId, userId, detail: { executionId } });
    let status = null;
    let reason = null;
    try {
      const result = await fn.apply(this, args);
      if (result?.status === "NOT_ADMITTED") return result;
      try {
        const row = (await pool.query("SELECT status, failure_reason FROM pipeline_executions WHERE id = $1", [executionId])).rows[0];
        status = row?.status || null;
        reason = row?.failure_reason || null;
      } catch { status = result?.status || null; }
      return result;
    } catch (err) {
      status = "FAILED";
      reason = String(err?.message || err).slice(0, 500);
      throw err;
    } finally {
      if (status !== null || reason !== null) {
        const outcome = outcomeOf(status);
        metrics.pipelineRuns.inc({ status: outcome });
        logEvent({
          level: outcome === "failed" ? "error" : "info",
          event: outcome === "failed" ? "pipeline_failed" : "pipeline_finished",
          projectId, userId,
          detail: { executionId, status, reason, durationMs: Date.now() - started },
        });
      }
    }
  };
}

module.exports = { instrumentStage, instrumentPipeline, outcomeOf };
