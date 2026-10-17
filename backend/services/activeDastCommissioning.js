'use strict';
// Commissioning is a server-selected authorization state, never a readiness
// assertion or a request-body capability snapshot.
const STATE='COMMISSIONING';
const UNKNOWN=Object.freeze(['zapApplicationProxyVerified','rateEnforcementVerified','redirectEnforcementVerified','jobCompletionVerified','timeoutVerified','cancellationVerified']);
const fail=code=>Object.assign(new Error(code),{code,status:403,nonRetryable:true});
function setupAllowed(context){return process.env.DAST_COMMISSIONING_SETUP_ENABLED==='true'&&!!selection(context);}
function activeAllowed(context,now=Date.now()){
 if(require('./commissioningControl').read(context,now)&&selection(context,now))return true;
 if(process.env.DAST_ACTIVE_ENABLED!=='true'||process.env.DAST_ACTIVE_COMMISSIONING_PHASE!=='ACTIVE_COMMISSIONING'||!selection(context,now))return false;
 let scope;try{scope=JSON.parse(process.env.DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT||'');}catch(_){return false;}
 const legacy=process.env.NODE_ENV!=='production'&&Object.keys(scope||{}).sort().join(',')==='executionId,expiresAt,projectId,userId';
 const leased=Object.keys(scope||{}).sort().join(',')==='executionId,expiresAt,leaseId,projectId,userId'&&/^[0-9a-f-]{36}$/.test(scope?.leaseId||'');
 return !!scope&&(legacy||leased)&&['projectId','executionId','userId'].every(k=>scope[k]===context[k])&&Number.isSafeInteger(scope.expiresAt)&&scope.expiresAt>now&&scope.expiresAt<=now+300000;
}
function runtimeAllowed(a){return a?.authorizationState==='COMMISSIONING'
 ?(require('./module2ActiveDast').isBaselineAuthorization(a)?setupAllowed(a):activeAllowed(a))
 :process.env.DAST_ACTIVE_ENABLED==='true';}
function selection(context,now=Date.now()) {
  if(process.env.DAST_ACTIVE_COMMISSIONING_ENABLED!=='true')return null;
  const issued=require('./activeOperatorEnrollment').scopeFor(context,{includeExpired:true});if(issued){if(issued.expiresAt<=now)throw fail('COMMISSIONING_CONTEXT_BLOCKED');return issued;}
  // Global enablement is availability, not selection of an ordinary execution.
  // Dynamic commissioning scopes above remain authoritative, including expiry.
  if(!process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT?.trim())return null;
  let scope;try{scope=JSON.parse(process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT||'');}catch(_){throw fail('COMMISSIONING_CONTEXT_BLOCKED');}
  if(!scope||Object.keys(scope).sort().join(',')!=='executionId,expiresAt,projectId,userId'||
     !['projectId','executionId','userId'].every(k=>Number.isSafeInteger(scope[k])&&scope[k]>0)||scope.projectId===17||
     !Number.isSafeInteger(scope.expiresAt)||scope.expiresAt<=now||scope.expiresAt>now+900000)throw fail('COMMISSIONING_CONTEXT_BLOCKED');
  if(!['projectId','executionId','userId'].every(k=>scope[k]===context[k]))return null;
  return Object.freeze({...scope,authorizationState:STATE});
}
function validate(a,context,now=Date.now()) {
  if(a?.authorizationState===undefined){if(selection(context,now))throw fail('COMMISSIONING_AUTHORIZATION_BLOCKED');return false;}
  if(a.authorizationState!==STATE)throw fail('COMMISSIONING_AUTHORIZATION_BLOCKED');
  const scope=selection(context,now),catalog=require('./activeRuntimeArtifacts').artifacts;
  if(!scope||a.expiresAt>scope.expiresAt||a.fixtureKind!==require('./dastFixture').PYTHON_KIND||
     a.zapImageDigest!==catalog.zap.imageId||a.fixtureImageDigest!==catalog.fixture.imageId||
     a.gatewayImageDigest!==require('./dastGateway').IMAGE||!/^[a-f0-9]{64}$/.test(a.gatewayContainerId||''))throw fail('COMMISSIONING_AUTHORIZATION_BLOCKED');
  return true;
}
function bind(context,catalog,now=Date.now()) {
  const scope=selection(context,now);if(!scope)return {};
  return {authorizationState:STATE,fixtureImageDigest:catalog.fixture.imageId,gatewayImageDigest:require('./dastGateway').IMAGE,expiresAt:Math.min(now+300000,scope.expiresAt)};
}
function assertReady(catalog) {
  // Only the six scan-dependent boolean fields may remain unknown. This still
  // requires the complete authenticated runtime, policy, initialization and
  // immutable artifact contract; historical helper traffic is not substituted.
  const e=catalog?.verifiedConfiguration;
  if(catalog?.zap?.imageId!==require('../config/zap-containment-diagnostic.json').imageId||
     catalog?.fixture?.imageId!==require('./dastFixture').pythonArtifact().imageId||
     [catalog.zap,catalog.fixture].some(x=>x.reference!==x.imageId||x.os!=='linux'||x.architecture!=='amd64')||
     catalog.fixture.sourceSha256!==require('./dastFixture').pythonArtifact().sourceSha256||
     !e||e.zapImageId!==catalog.zap.imageId||e.fixtureImageId!==catalog.fixture.imageId||
     e.scope!=='ZAP_SHARED_NETWORK_NAMESPACE_HELPER'||e.diagnosticCasesPassed!==12||
     !/^[a-f0-9]{64}$/.test(e.diagnosticReportSha256||'')||e.productionReady!==false)throw fail('COMMISSIONING_SAFETY_EVIDENCE_BLOCKED');
  const ids=require('./dastActiveScanner').POLICY.approvedPluginIds;
  const sameIds=v=>Array.isArray(v)&&JSON.stringify([...v].sort())===JSON.stringify([...ids].sort());
  if(!sameIds(e.activeRuleIds)||!sameIds(e.policyConfiguration?.enabledRuleIds)||
     ids.some(id=>e.policyConfiguration.strengths?.[id]!=='LOW'||e.policyConfiguration.thresholds?.[id]!=='LOW')||
     !/^[a-f0-9]{64}$/.test(e.policyConfiguration?.evidenceSha256||'')||
     e.traditionalJsonExportConfigured!==true||e.rateConfiguredRequestsPerSecond!==2||e.concurrencyConfigured!==1||
     Object.entries(require('./zapInitialization').expectedAddons).some(([id,version])=>String(e.loadedAddons?.[id]).split('.').concat('0','0').slice(0,3).join('.')!==String(version).split('.').concat('0','0').slice(0,3).join('.')))throw fail('COMMISSIONING_SAFETY_EVIDENCE_BLOCKED');
  // Existing genuine non-scanning evidence can authorize commissioning only.
  // Fresh initialization, writable paths, listeners, API authentication, policy
  // and target-specific rate settings are re-observed before any Active job.
  if(!catalog.zap.capabilities)return catalog;
  return require('./activeZapRuntime').capabilities(catalog,{commissioning:true});
}
function assertContextReady(context,catalog=require('./activeRuntimeArtifacts').artifacts) {
  return selection(context)?assertReady(catalog):require('./activeRuntimeArtifacts').assertReady(catalog);
}
function assertAuthorizationReady(a,catalog=require('./activeRuntimeArtifacts').artifacts) {
  return validate(a,a)?assertReady(catalog):require('./activeRuntimeArtifacts').assertReady(catalog);
}
function benignRequest(a) {
  require('./module2ActiveDast').validateAuthorization(a,a);
  if(!validate(a,a))throw fail('COMMISSIONING_AUTHORIZATION_BLOCKED');
  const request=`GET http://${a.hostname}:18080/test/sqli?id=1 HTTP/1.1\r\nHost: ${a.hostname}:18080\r\nConnection: close\r\n\r\n`;
  return Object.freeze({component:'core',type:'action',name:'sendRequest',request,followRedirects:false,timeoutMs:10000,maxResponseBytes:65536});
}
function evidenceSummary(observation,cleanup,reason) {
  // No automatic promotion, including after successful completion. In particular
  // neither cancellation nor timeout is inferred from ordinary scan success.
  return {authorizationState:STATE,productionReady:false,independentReviewRequired:true,
    applicationTraffic:observation?.commissioningTraffic?.verified===true?'OBSERVED':'UNVERIFIED',
    completion:observation?.completed===true?'OBSERVED':'UNVERIFIED',
    rateEnforcement:'UNVERIFIED',concurrencyEnforcement:'UNVERIFIED',
    cancellation:observation?.cancelled===true?'OBSERVED':reason==='ACTIVE_CANCELLED'?'REQUESTED_UNVERIFIED':'NOT_EXERCISED',
    timeout:observation?.timedOut===true?'OBSERVED':reason==='ACTIVE_TIMED_OUT'?'EXERCISED_UNVERIFIED':'NOT_EXERCISED',
    redirectBehavior:'UNVERIFIED',cleanup:cleanup?.cleaned===true?'CLEANED':'FAILED',
    ...(observation?.commissioningTraffic?.verified===true?{traffic:observation.commissioningTraffic}:{})};
}
module.exports={STATE,UNKNOWN,selection,validate,bind,assertReady,assertContextReady,assertAuthorizationReady,benignRequest,evidenceSummary,setupAllowed,activeAllowed,runtimeAllowed};
