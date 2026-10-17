'use strict';
const {randomUUID}=require('crypto');
const {validateAuthorization}=require('./module2ActiveDast');
const fail=code=>Object.assign(new Error(code),{code,status:403,nonRetryable:true});
const validId=v=>Number.isSafeInteger(v)&&v>0;
async function audit(db,c,event,reason){
  if(event==='REJECTED'&&!reason.startsWith('COMMISSIONING_')){
    try{if(require('./activeDastCommissioning').selection(c))reason='COMMISSIONING_'+reason;}
    catch(_){reason='COMMISSIONING_SCOPE_REJECTED';}
  }
  await db.query('INSERT INTO active_dast_audit (operator_id,project_id,pipeline_execution_id,event,reason) VALUES ($1,$2,$3,$4,$5)',[validId(c.userId)?c.userId:null,validId(c.projectId)?c.projectId:null,validId(c.executionId)?c.executionId:null,event,reason]);
}
async function issue(pool,context,targetId) {
  const started=require('perf_hooks').performance.now();
  let client,commissioningPhase;
  try {
    if(![context.projectId,context.executionId,context.userId].every(validId)||context.projectId===17||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(targetId||''))throw fail('ACTIVE_AUTHORIZATION_BLOCKED');
    client=await pool.connect();await client.query('BEGIN');
    const op=await client.query('SELECT o.user_id FROM active_dast_operators o JOIN projects p ON p.user_id=o.user_id JOIN pipeline_executions e ON e.project_id=p.id WHERE o.user_id=$1 AND o.enabled=TRUE AND p.id=$2 AND e.id=$3 AND e.status=\'RUNNING\' FOR SHARE OF o,p,e',[context.userId,context.projectId,context.executionId]);
    if(op.rows.length!==1)throw fail('ACTIVE_OPERATOR_REQUIRED');
    await require('./activeOperatorEnrollment').assertProjectRole(client,context);
    if(require('./activeDastCommissioning').selection(context)){await require('./activeDastPrerequisites').check(client,context);commissioningPhase=await require('./commissioningPhases').assertIssuable(client,context);}
    require('./activeDastCommissioning').assertContextReady(context);
    const target=await client.query('SELECT * FROM active_dast_targets WHERE id=$1 AND project_id=$2 AND pipeline_execution_id=$3 AND verified_until>NOW() FOR SHARE',[targetId,context.projectId,context.executionId]);
    if(target.rows.length!==1)throw fail('ACTIVE_TARGET_UNVERIFIED');
    const t=target.rows[0];
    if(!/^[a-f0-9]{64}$/.test(t.fixture_container_id)||!/^[a-f0-9]{64}$/.test(t.scanner_network_id))throw fail('ACTIVE_TARGET_UNVERIFIED');
    const authorization={...t.authorization,...context,targetId,fixtureContainerId:t.fixture_container_id,scannerNetworkId:t.scanner_network_id,policies:['SQLI','XSS'],expiresAt:Math.min(Date.now()+300000,new Date(t.verified_until).getTime())};
    validateAuthorization(authorization,context);
    if(authorization.authorizationState==='COMMISSIONING'){
      const budget=require('./commissioningBudget');
      budget.requireTime(budget.approvedDeadline(context,[authorization.expiresAt,new Date(commissioningPhase?.expires_at).getTime(),t.authorization.expiresAt]),budget.minimumFor(authorization));
    }
    const id=randomUUID();await client.query('INSERT INTO active_dast_grants (id,target_id,project_id,pipeline_execution_id,operator_id,"authorization",expires_at) VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7/1000.0))',[id,targetId,context.projectId,context.executionId,context.userId,JSON.stringify(authorization),authorization.expiresAt]);
    await audit(client,context,'ISSUED',authorization.authorizationState==='COMMISSIONING'?'COMMISSIONING_EXACT_DISPOSABLE_TARGET':'EXACT_DISPOSABLE_TARGET');await client.query('COMMIT');return {grantId:id,expiresAt:authorization.expiresAt,durationMs:Math.round(require('perf_hooks').performance.now()-started)};
  } catch(error) {
    if(client)await client.query('ROLLBACK').catch(()=>{});
    // Audit failure itself blocks issuance; never quietly permit an unaudited grant.
    await audit(pool,context,'REJECTED',/^[A-Z_]{1,64}$/.test(error.code||'')?error.code:'ISSUANCE_FAILED');throw error;
  } finally {client?.release();}
}
async function consume(pool,context) {
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    await require('./activeOperatorEnrollment').assertProjectRole(client,context);
    if(require('./activeDastCommissioning').selection(context)){await require('./activeDastPrerequisites').check(client,context);await require('./commissioningPhases').assertActive(client,context);}
    const result=await client.query(`UPDATE active_dast_grants g SET consumed_at=NOW()
      FROM active_dast_operators o, projects p, pipeline_executions e, active_dast_targets t
      WHERE g.project_id=$1 AND g.pipeline_execution_id=$2 AND g.operator_id=$3
      AND g.consumed_at IS NULL AND g.expires_at>NOW() AND g.project_id<>17
      AND o.user_id=g.operator_id AND o.enabled=TRUE AND p.id=g.project_id AND p.user_id=g.operator_id
      AND e.id=g.pipeline_execution_id AND e.project_id=p.id AND t.id=g.target_id
      AND e.status='RUNNING'
      AND EXISTS (SELECT 1 FROM deployment_history d JOIN dast_scans s
        ON s.project_id=d.project_id AND s.pipeline_execution_id=d.pipeline_execution_id
        WHERE d.project_id=p.id AND d.pipeline_execution_id=e.id AND d.status='SUCCESS'
        AND s.status='COMPLETED' AND s.scan_mode='BASELINE'
        AND (s.target_url=d.staging_url OR (d.staging_url ~ '^https?://[^/?#]+/$' AND s.target_url=left(d.staging_url,length(d.staging_url)-1)))
        AND d.staging_url ~ '^https?://' AND d.staging_url<>'http://minikube-url-unavailable')
      AND t.project_id=p.id AND t.pipeline_execution_id=e.id AND t.verified_until>NOW()
      RETURNING g.authorization,g.expires_at AS grant_expires_at,t.verified_until AS target_verified_until,t.authorization AS target_authorization,t.id AS target_id,t.fixture_container_id,t.scanner_network_id`,[context.projectId,context.executionId,context.userId]);
    if(result.rows.length!==1)throw fail('ACTIVE_GRANT_MISSING_OR_CONSUMED');
    const a=result.rows[0].authorization;validateAuthorization(a,context);
    const observed=result.rows[0];
    const enrolled=observed.target_authorization;
    if(!enrolled||['projectId','executionId','userId','targetId','fixtureKind','hostname','ip','port','scheme','routes','policies','zapImageDigest','fixtureContainerId','scannerNetworkId','authorizationState','fixtureImageDigest','gatewayImageDigest','gatewayContainerId','baselineScanId','stagingEvidenceSha256','retainedScannerId'].some(k=>JSON.stringify(a[k])!==JSON.stringify(enrolled[k]))||a.expiresAt>enrolled.expiresAt)throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    if(a.targetId!==observed.target_id || a.fixtureContainerId!==observed.fixture_container_id || a.scannerNetworkId!==observed.scanner_network_id || !/^[a-f0-9]{64}$/.test(a.fixtureContainerId||'') || !/^[a-f0-9]{64}$/.test(a.scannerNetworkId||'') || JSON.stringify(a.policies)!=='["SQLI","XSS"]')throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    // Bind the runtime to actual PostgreSQL expiries as well as the signed
    // authorization payload; a JSON expiry must never outlive the grant row.
    a.expiresAt=require('./commissioningBudget').earliest([a.expiresAt,new Date(observed.grant_expires_at).getTime(),new Date(observed.target_verified_until).getTime()]);
    validateAuthorization(a,context);
    await audit(client,context,'CONSUMED',a.authorizationState==='COMMISSIONING'?'COMMISSIONING_ATOMIC_SINGLE_USE':'ATOMIC_SINGLE_USE');await client.query('COMMIT');return a;
  } catch(error) {await client.query('ROLLBACK').catch(()=>{});await audit(pool,context,'REJECTED','CONSUMPTION_BLOCKED');throw error;}
  finally {client.release();}
}
module.exports={issue,consume};
