'use strict';
const blocked=code=>Object.assign(new Error(code),{code,status:403,nonRetryable:true});
function context(c){if(!c||![c.projectId,c.executionId,c.userId].every(n=>Number.isSafeInteger(n)&&n>0)||c.projectId===17)throw blocked('ACTIVE_AUTHORIZATION_BLOCKED');return c;}
function staging(value){try{const u=new URL(value);if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.hash||u.hostname==='minikube-url-unavailable')throw Error();return u.href;}catch(_){throw blocked('ACTIVE_STAGING_GATE_BLOCKED');}}
async function check(pool,c){
 context(c);
 const operator=await pool.query("SELECT o.user_id FROM active_dast_operators o JOIN projects p ON p.user_id=o.user_id JOIN pipeline_executions e ON e.project_id=p.id WHERE o.user_id=$1 AND o.enabled=TRUE AND p.id=$2 AND e.id=$3 AND e.status='RUNNING'",[c.userId,c.projectId,c.executionId]);
 if(operator.rows.length!==1)throw blocked('ACTIVE_OPERATOR_OR_EXECUTION_BLOCKED');
 await require('./activeOperatorEnrollment').assertProjectRole(pool,c);
 if(require('./activeDastCommissioning').selection(c))return require('./commissioningFixtureStage').verify(pool,c);
 const deployed=await pool.query("SELECT staging_url FROM deployment_history WHERE project_id=$1 AND pipeline_execution_id=$2 AND status='SUCCESS' ORDER BY id DESC LIMIT 1",[c.projectId,c.executionId]);
 const url=staging(deployed.rows[0]?.staging_url);
 const baseline=await pool.query("SELECT target_url FROM dast_scans WHERE project_id=$1 AND pipeline_execution_id=$2 AND scan_mode='BASELINE' AND status='COMPLETED' ORDER BY id DESC LIMIT 1",[c.projectId,c.executionId]);
 if(baseline.rows.length!==1||staging(baseline.rows[0].target_url)!==url)throw blocked('ACTIVE_BASELINE_GATE_BLOCKED');
 return {stagingUrl:url};
}
async function baselineTarget(pool,{projectId,executionId,configuredTarget}){
 if(!executionId)return String(configuredTarget||'').trim();
 const result=await pool.query("SELECT staging_url FROM deployment_history WHERE project_id=$1 AND pipeline_execution_id=$2 AND status='SUCCESS' ORDER BY id DESC LIMIT 1",[projectId,executionId]);
 staging(result.rows[0]?.staging_url);return result.rows[0].staging_url.trim();
}
module.exports={context,staging,check,baselineTarget,blocked};
