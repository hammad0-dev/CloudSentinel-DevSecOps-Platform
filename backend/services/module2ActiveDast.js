"use strict";
const {isIP}=require('net');
const {automationPlan,POLICY}=require('./dastActiveScanner');
const {extractFindings,summarize,fingerprint}=require('./dastBaselineScanner');
const ROUTES=['/test/sqli','/test/xss'];
const issued=new WeakSet(),consumed=new WeakSet();
function failure(code){return Object.assign(new Error(code),{code,nonRetryable:true});}
function validateAuthorization(a,context,now=Date.now()) {
  if(![context.projectId,context.executionId,context.userId].every(v=>Number.isSafeInteger(v)&&v>0) || context.projectId===17)throw failure('ACTIVE_AUTHORIZATION_BLOCKED');
  if(!a || !Number.isSafeInteger(a.expiresAt) || a.expiresAt<=now || a.expiresAt>now+900000 || a.projectId!==context.projectId || a.executionId!==context.executionId || a.userId!==context.userId || a.fixtureKind!=='cloudsentinel-vulnerable-v1' || !/^[a-z0-9][a-z0-9-]{0,40}\.test$/.test(a.hostname||'') || isIP(a.ip)!==4 || !/^172\.30\./.test(a.ip) || a.port!==18080 || a.scheme!=='http' || JSON.stringify(a.routes)!==JSON.stringify(ROUTES) || !/^sha256:[a-f0-9]{64}$/.test(a.zapImageDigest||'')) throw failure('ACTIVE_AUTHORIZATION_BLOCKED');
  return a;
}
// Trusted server-side authorization issuance; never accepts request-body evidence.
// A future approval API must authenticate the owner and bind a provisioned fixture
// before invoking this function. No approval endpoint is exposed by this change.
function issueAuthorization(a,context){validateAuthorization(a,context);const grant=Object.freeze({...a,routes:Object.freeze([...a.routes])});issued.add(grant);return grant;}
function normalize(report,authorization,passive=[]) {
  if(!report || !Array.isArray(report.site) || Buffer.byteLength(JSON.stringify(report))>2*1024*1024)throw failure('ACTIVE_REPORT_INVALID');
  const allowed=new Set(POLICY.approvedPluginIds),seen=new Set(passive.map(f=>fingerprint(f))),result=[];
  for(const site of report.site) {
    if(!Array.isArray(site.alerts))throw failure('ACTIVE_REPORT_INVALID');
    for(const alert of site.alerts) {
      if(!allowed.has(String(alert.pluginid)))continue; // Passive alerts stay passive.
      if(!Array.isArray(alert.instances)||!alert.instances.length)throw failure('ACTIVE_REPORT_INVALID');
      for(const f of extractFindings({site:[{alerts:[alert]}]})) {
        const url=new URL(f.endpoint);
        if(url.origin!==`http://${authorization.hostname}:${authorization.port}` || !ROUTES.includes(url.pathname) || url.username || url.password || url.hash)throw failure('ACTIVE_REPORT_OUT_OF_SCOPE');
        const redact=s=>String(s).replace(/(?:authorization|cookie|password|token|secret)\s*[:=]\s*[^\r\n]*/gi,'[REDACTED]').replace(/<[^>]*>/g,'').slice(0,1000);
        Object.assign(f,{plugin_id:String(alert.pluginid),classification:['40012','40014','40016','40017'].includes(String(alert.pluginid))?'XSS':'SQLI',confidence:String(alert.confidence||'UNKNOWN').slice(0,32),owasp_category:'A03:2021 Injection',response_details:redact(f.response_details),request_payload:redact(f.request_payload)});
        f.finding_fingerprint=fingerprint(f);
        if(!seen.has(f.finding_fingerprint)){seen.add(f.finding_fingerprint);result.push(f);}
      }
    }
  }
  return result;
}
async function execute({pool,projectId,executionId,userId,authorization,signal},runtime) {
  if(process.env.DAST_ACTIVE_ENABLED!=='true')return {status:'DISABLED',scanMode:'ACTIVE'};
  let status='BLOCKED',session,result,cleanup={cleaned:true,residual:[]};const start=Date.now();
  try {
    if(process.env.NODE_ENV!=='test') {
      require('./activeRuntimeArtifacts').assertReady();
      authorization=issueAuthorization(await require('./activeDastGrants').consume(pool,{projectId,executionId,userId}),{projectId,executionId,userId});
      runtime=require('./activeRuntimeRegistry').consume(authorization);
    }
    if(!issued.has(authorization)||consumed.has(authorization))throw failure('ACTIVE_AUTHORIZATION_BLOCKED');
    validateAuthorization(authorization,{projectId,executionId,userId});consumed.add(authorization);
    const deployment=await pool.query("SELECT id FROM deployment_history WHERE project_id=$1 AND pipeline_execution_id=$2 AND status='SUCCESS' ORDER BY id DESC LIMIT 1",[projectId,executionId]);
    if(!deployment.rows.length)throw failure('ACTIVE_DEPLOYMENT_GATE_BLOCKED');
    if(!runtime)throw failure('ACTIVE_RUNTIME_NOT_IMPLEMENTED');
    if(process.env.NODE_ENV!=='test' && !(runtime instanceof require('./activeZapRuntime').ActiveZapRuntime))throw failure('ACTIVE_RUNTIME_BLOCKED');
    if(signal?.aborted)throw failure('ACTIVE_CANCELLED');
    // Runtime must own ZAP itself, not attest a different acceptance client.
    session=await runtime.provision({authorization,signal});
    await runtime.verify(session,authorization);
    const controller=new AbortController();let timer,abort;
    const stopped=new Promise((_,reject)=>{
      timer=setTimeout(()=>{controller.abort();reject(failure('ACTIVE_TIMED_OUT'));},600000);
      abort=()=>{controller.abort();reject(failure('ACTIVE_CANCELLED'));};signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
    });
    let observation;
    try {
      observation=await Promise.race([runtime.scan(session,{plans:ROUTES.map(route=>automationPlan(`http://${authorization.hostname}:${authorization.port}${route}`)),signal:controller.signal,maxRequestsPerSecond:2,maxConcurrency:1}),stopped]);
    } finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);}
    await runtime.verify(session,authorization);
    if(observation?.completed!==true || observation?.exitCode!==0 || observation?.errors?.length || observation?.cancelled || observation?.timedOut)throw failure('ACTIVE_SCAN_INCOMPLETE');
    const passive=await pool.query("SELECT f.alert,f.attack_type,f.severity,f.endpoint,f.method,f.param,f.request_payload,f.cwe_id FROM dast_findings f JOIN dast_scans s ON s.id=f.scan_id AND s.project_id=f.project_id WHERE s.project_id=$1 AND s.pipeline_execution_id=$2 AND s.scan_mode='BASELINE' AND s.status='COMPLETED'",[projectId,executionId]);
    const findings=normalize(observation.report,authorization,passive.rows);
    result={findings,summary:summarize(findings),authorization:{projectId,executionId,origin:`http://${authorization.hostname}:18080`,ip:authorization.ip,zapImageDigest:authorization.zapImageDigest}};
    status=findings.length?'COMPLETED_WITH_FINDINGS':'COMPLETED_NO_FINDINGS';
  } catch(error) {status=error.code==='ACTIVE_CANCELLED'?'CANCELLED':error.code==='ACTIVE_TIMED_OUT'?'TIMED_OUT':/BLOCKED|NOT_IMPLEMENTED/.test(error.code||'')?'BLOCKED':'FAILED';result={reason:error.code||'ACTIVE_SCAN_FAILED'};}
  finally {if(runtime)try{cleanup=await runtime.cleanup(session);if(cleanup?.cleaned!==true || !Array.isArray(cleanup.residual) || cleanup.residual.length)status='CLEANUP_FAILED';}catch(_){cleanup={cleaned:false,residual:[{type:'active-runtime'}]};status='CLEANUP_FAILED';}}
  return {scanMode:'ACTIVE',status,durationMs:Date.now()-start,cleanup,...result};
}
module.exports={execute,issueAuthorization,validateAuthorization,normalize,ROUTES};
