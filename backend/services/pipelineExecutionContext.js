"use strict";

function invalidExecutionContext(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

async function resolvePipelineExecutionId(pool, user, projectId) {
  const executionId = user?.pipelineExecutionId;
  if (executionId === undefined || executionId === null) return null;

  if (user?.pipelineOrchestrator !== true || !Number.isInteger(executionId) || executionId < 1) {
    throw invalidExecutionContext("Invalid pipeline execution context");
  }

  const result = await pool.query(
    "SELECT id FROM pipeline_executions WHERE id = $1 AND project_id = $2 AND status = 'RUNNING'",
    [executionId, projectId]
  );
  if (!result.rows.length) {
    throw invalidExecutionContext("Pipeline execution does not belong to this running project pipeline");
  }
  return executionId;
}

module.exports = { resolvePipelineExecutionId };