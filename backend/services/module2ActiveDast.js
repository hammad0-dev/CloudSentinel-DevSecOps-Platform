"use strict";
const {isIP}=require('net');
const {performance}=require('perf_hooks');
const {automationPlan,POLICY}=require('./dastActiveScanner');
const {extractFindings,summarize,fingerprint}=require('./dastBaselineScanner');
const ROUTES=['/test/sqli','/test/xss'];
const issued=new WeakSet(),consumed=new WeakSet();
const baselineIssued=new WeakSet();
function plans(a){return a.authorizationState==='COMMISSIONING'?[require('./dastActiveScanner').commissioningPlan(`http://${a.hostname}:${a.port}`)]:ROUTES.map(route=>automationPlan(`http://${a.hostname}:${a.port}${route}`,POLICY));}
function failure(code){return Object.assign(new Error(code),{code,nonRetryable:true});}
function validateAuthorization(a,context,now=Date.now()) {
  if(![context.projectId,context.executionId,context.userId].every(v=>Number.isSafeInteger(v)&&v>0) || context.projectId===17)throw failure('ACTIVE_AUTHORIZATION_BLOCKED');
  if(!a || !Number.isSafeInteger(a.expiresAt) || a.expiresAt<=now || a.expiresAt>now+900000 || a.projectId!==context.projectId || a.executionId!==context.executionId || a.userId!==context.userId || a.fixtureKind!=='cloudsentinel-vulnerable-v1' || !/^[a-z0-9][a-z0-9-]{0,40}\.test$/.test(a.hostname||'') || isIP(a.ip)!==4 || !/^172\.30\./.test(a.ip) || a.port!==18080 || a.scheme!=='http' || JSON.stringify(a.routes)!==JSON.stringify(ROUTES) || !/^sha256:[a-f0-9]{64}$/.test(a.zapImageDigest||'')) throw failure('ACTIVE_AUTHORIZATION_BLOCKED');
  require('./activeDastCommissioning').validate(a,context,now);
  return a;
}
// Trusted server-side authorization issuance; never accepts request-body evidence.
// A future approval API must authenticate the owner and bind a provisioned fixture
// before invoking this function. No approval endpoint is exposed by this change.
function issueAuthorization(a,context){validateAuthorization(a,context);const grant=Object.freeze({...a,routes:Object.freeze([...a.routes])});issued.add(grant);return grant;}
function issueBaselineAuthorization(a,context){if(!require('./activeDastCommissioning').setupAllowed(context))throw failure('COMMISSIONING_SETUP_BLOCKED');const grant=issueAuthorization(a,context);baselineIssued.add(grant);return grant;}
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
        f.cwe_id=f.classification==='XSS'?79:89;
        f.finding_fingerprint=fingerprint(f);
        if(!seen.has(f.finding_fingerprint)){seen.add(f.finding_fingerprint);result.push(f);}
      }
    }
  }
  return result;
}
async function execute({pool,projectId,executionId,userId,authorization,signal},runtime) {
  if(process.env.DAST_ACTIVE_ENABLED!=='true'&&!require('./activeDastCommissioning').activeAllowed({projectId,executionId,userId}))return {status:'DISABLED',scanMode:'ACTIVE'};
  let status='BLOCKED',session,result,observation,cleanup={cleaned:true,residual:[]};const start=Date.now();
  let budget,phaseDeadline,retainedDeadline;const context={projectId,executionId,userId};
  const continuationTimings={};
  const timed=async(name,operation)=>{const started=performance.now();try{return await operation();}finally{continuationTimings[name]=Math.round(performance.now()-started);}};
  try {
    if(process.env.NODE_ENV!=='test') {
      await timed('initialPrerequisitesMs',()=>require('./activeDastPrerequisites').check(pool,context));
      if(signal?.aborted)throw failure('ACTIVE_CANCELLED');
      require('./activeDastCommissioning').assertContextReady({projectId,executionId,userId});
      if(require('./activeDastCommissioning').selection(context))phaseDeadline=new Date((await timed('phaseValidationMs',()=>require('./commissioningPhases').assertActive(pool,context))).expires_at).getTime();
      const pendingTarget=await timed('grantLookupMs',()=>require('./activeRuntimeRegistry').waitForGrant(pool,context,signal));
      await timed('freshPendingVerificationMs',()=>require('./activeRuntimeRegistry').verifyPending(pendingTarget));
      retainedDeadline=pendingTarget.expiresAt;
      if(pendingTarget.authorizationState==='COMMISSIONING'){const b=require('./commissioningBudget');b.requireTime(b.approvedDeadline(context,[phaseDeadline,retainedDeadline]),b.minimumFor(pendingTarget));}
      if(signal?.aborted)throw failure('ACTIVE_CANCELLED');
      if(process.env.DAST_ACTIVE_ENABLED!=='true'&&!require('./activeDastCommissioning').activeAllowed({projectId,executionId,userId}))throw failure('ACTIVE_RUNTIME_BLOCKED');
      await timed('preConsumptionPrerequisitesMs',()=>require('./activeDastPrerequisites').check(pool,context));
      authorization=issueAuthorization(await timed('grantConsumptionMs',()=>require('./activeDastGrants').consume(pool,context)),context);
      runtime=require('./activeRuntimeRegistry').consume(authorization);
    }
    if(!issued.has(authorization)||consumed.has(authorization))throw failure('ACTIVE_AUTHORIZATION_BLOCKED');
    validateAuthorization(authorization,{projectId,executionId,userId});consumed.add(authorization);
    if(baselineIssued.has(authorization)||(authorization.authorizationState==='COMMISSIONING'&&!require('./activeDastCommissioning').activeAllowed(authorization)))throw failure('COMMISSIONING_ACTIVE_AUTHORIZATION_BLOCKED');
    const deployment=await pool.query("SELECT id FROM deployment_history WHERE project_id=$1 AND pipeline_execution_id=$2 AND status='SUCCESS' ORDER BY id DESC LIMIT 1",[projectId,executionId]);
    if(!deployment.rows.length)throw failure('ACTIVE_DEPLOYMENT_GATE_BLOCKED');
    if(!runtime)throw failure('ACTIVE_RUNTIME_NOT_IMPLEMENTED');
    if(process.env.NODE_ENV!=='test' && !(runtime instanceof require('./activeZapRuntime').ActiveZapRuntime))throw failure('ACTIVE_RUNTIME_BLOCKED');
    if(signal?.aborted)throw failure('ACTIVE_CANCELLED');
    if(authorization.authorizationState==='COMMISSIONING'){
      const b=require('./commissioningBudget');
      // Test runtimes have no durable phase; production requires both inspected
      // pending-runtime and durable execution deadlines, never caller snapshots.
      const deadlines=process.env.NODE_ENV==='test'?[authorization.expiresAt]:[phaseDeadline,retainedDeadline,authorization.expiresAt];
      budget=b.start(b.approvedDeadline(context,deadlines),{signal,authorization});
    }
    const workSignal=budget?.signal||signal;
    const work=async()=>{
    budget?.check();
    // Runtime must own ZAP itself, not attest a different acceptance client.
    session=await timed('provisionMs',()=>runtime.provision({authorization,signal:workSignal}));
    budget?.check();
    await runtime.verify(session,authorization);budget?.check();
    const controller=new AbortController();let timer,abort;
    if(budget){
      observation=await runtime.scan(session,{plans:plans(authorization),signal:workSignal,maxRequestsPerSecond:2,maxConcurrency:1});
    }else{
    const stopped=new Promise((_,reject)=>{
      timer=setTimeout(()=>{controller.abort();reject(failure('ACTIVE_TIMED_OUT'));},600000);
      abort=()=>{controller.abort();reject(failure('ACTIVE_CANCELLED'));};workSignal?.addEventListener('abort',abort,{once:true});if(workSignal?.aborted)abort();
    });
    try {
      // A commissioning grant cannot silently enter the ordinary scan path.
      // The transaction-correlated application collector must run first; the
      // shared-namespace helper is explicitly insufficient for this step.
      observation=await Promise.race([runtime.scan(session,{plans:plans(authorization),signal:controller.signal,maxRequestsPerSecond:2,maxConcurrency:1}),stopped]);
    } finally {clearTimeout(timer);workSignal?.removeEventListener('abort',abort);}
    }
    await runtime.verify(session,authorization);budget?.check();
    if(observation?.completed!==true || observation?.exitCode!==0 || observation?.errors?.length || observation?.cancelled || observation?.timedOut)throw failure('ACTIVE_SCAN_INCOMPLETE');
    if(authorization.authorizationState==='COMMISSIONING'&&observation.commissioningTraffic?.verified!==true)throw failure('COMMISSIONING_APPLICATION_TRAFFIC_BLOCKED');
    const passive=await pool.query("SELECT f.alert,f.attack_type,f.severity,f.endpoint,f.method,f.param,f.request_payload,f.cwe_id FROM dast_findings f JOIN dast_scans s ON s.id=f.scan_id AND s.project_id=f.project_id WHERE s.project_id=$1 AND s.pipeline_execution_id=$2 AND s.scan_mode='BASELINE' AND s.status='COMPLETED'",[projectId,executionId]);
    budget?.check();
    const findings=normalize(observation.report,authorization,passive.rows);
    if(authorization.authorizationState==='COMMISSIONING'&&!['SQLI','XSS'].every(type=>findings.some(f=>f.classification===type)))throw failure('COMMISSIONING_FINDINGS_INCOMPLETE');
    result={findings,summary:summarize(findings),authorization:{projectId,executionId,origin:`http://${authorization.hostname}:18080`,ip:authorization.ip,zapImageDigest:authorization.zapImageDigest}};
    status=findings.length?'COMPLETED_WITH_FINDINGS':'COMPLETED_NO_FINDINGS';
    };
    if(budget)await budget.run(work);else await work();
  } catch(error) {status=error.code==='ACTIVE_CANCELLED'?'CANCELLED':error.code==='ACTIVE_TIMED_OUT'?'TIMED_OUT':/BLOCKED|NOT_IMPLEMENTED/.test(error.code||'')?'BLOCKED':'FAILED';result={reason:error.code||'ACTIVE_SCAN_FAILED',...(error.budget?{admission:error.budget}:{})};}
  finally {
    budget?.close();
    if(runtime)try{cleanup=await timed('cleanupMs',()=>runtime.cleanup(session));if(cleanup?.cleaned!==true || !Array.isArray(cleanup.residual) || cleanup.residual.length)status='CLEANUP_FAILED';}catch(_){cleanup={cleaned:false,residual:[{type:'active-runtime'}]};status='CLEANUP_FAILED';}
    if(process.env.NODE_ENV!=='test'&&!runtime)try{cleanup=await timed('cleanupMs',()=>require('./activeRuntimeRegistry').cancelPending(context));if(!cleanup.cleaned)status='CLEANUP_FAILED';}catch(_){cleanup={cleaned:false,residual:[{type:'active-enrollment'}]};status='CLEANUP_FAILED';}
    if(cleanup.evidence?.acceptance==='BLOCKED'&&status.startsWith('COMPLETED')){status='BLOCKED';result={reason:'ACTIVE_EVIDENCE_OR_RATE_UNVERIFIED',evidence:cleanup.evidence};}
    require('./commissioningFixtureStage').release({projectId,executionId,userId});
    if(budget&&Date.now()>=budget.deadline&&status.startsWith('COMPLETED')){status='TIMED_OUT';result={reason:'ACTIVE_TIMED_OUT'};}
  }
  return {scanMode:'ACTIVE',status,durationMs:Date.now()-start,cleanup,...result,continuationTimings:{source:'MONOTONIC_RUNTIME_CLOCK',...continuationTimings},...(budget?{timing:{deadline:budget.deadline,cleanupCompletedAt:Date.now(),runtime:observation?.timings,cleanupDurationMs:cleanup.durationMs}}:{}),...(authorization?.authorizationState==='COMMISSIONING'?{authorizationState:'COMMISSIONING',productionReady:false,commissioning:require('./activeDastCommissioning').evidenceSummary(observation,cleanup,result?.reason)}:{})};
}
module.exports={execute,issueAuthorization,issueBaselineAuthorization,validateAuthorization,normalize,ROUTES,plans,isIssuedAuthorization:a=>issued.has(a),isBaselineAuthorization:a=>baselineIssued.has(a)};
