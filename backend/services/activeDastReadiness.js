'use strict';
const required={active_dast_executions:['project_id','pipeline_execution_id','status','result'],active_dast_operators:['user_id','enabled'],active_dast_targets:['id','project_id','pipeline_execution_id','authorization','fixture_container_id','scanner_network_id','verified_until'],active_dast_grants:['id','target_id','project_id','pipeline_execution_id','operator_id','authorization','expires_at','consumed_at'],active_dast_audit:['event','reason']};
async function inspect({pool,adapter,context}){
 const checks=[];const add=(name,status,reason)=>checks.push({name,status,...(reason?{reason}: {})});
 add('active-disabled',process.env.DAST_ACTIVE_ENABLED==='false'?'PASS':'BLOCKED');
 add('runtime-host-uid-gid',process.getuid?.()===1000&&process.getgid?.()===1000?'PASS':'BLOCKED');
 try{await require('./nativeConnectArtifact').verifyAuditedBuild();add('audited-native-artifact','PASS');}catch(e){add('audited-native-artifact','BLOCKED',e.code||'NATIVE_ARTIFACT_UNAVAILABLE');}
 try{
  const cols=(await pool.query("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' AND table_name LIKE 'active_dast%'")).rows;
  const missing=Object.entries(required).flatMap(([t,columns])=>columns.filter(c=>!cols.some(v=>v.table_name===t&&v.column_name===c)).map(c=>t+'.'+c));
  if(cols.some(v=>v.column_name==='authorization'&&v.data_type!=='jsonb'))missing.push('authorization type');
  const fk=(await pool.query("SELECT c.relname,pg_get_constraintdef(k.oid) AS definition,k.convalidated FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('active_dast_executions','active_dast_targets','active_dast_grants')")).rows;
  for(const table of ['active_dast_executions','active_dast_targets','active_dast_grants'])if(!fk.some(k=>k.relname===table&&k.convalidated&&k.definition.includes('FOREIGN KEY (pipeline_execution_id, project_id)')))missing.push(table+' execution ownership');
  if(!fk.some(k=>k.relname==='active_dast_grants'&&k.convalidated&&k.definition.includes('FOREIGN KEY (target_id, project_id, pipeline_execution_id)')))missing.push('grant target ownership');
  for(const table of ['active_dast_targets','active_dast_grants'])if(!fk.some(k=>k.relname===table&&k.convalidated&&k.definition.includes('UNIQUE (project_id, pipeline_execution_id)')))missing.push(table+' single execution');
  add('migrations-012-013',missing.length?'BLOCKED':'PASS',missing.length?missing.join(', '):undefined);
 }catch(_){add('migrations-012-013','BLOCKED','SCHEMA_INSPECTION_FAILED');}
 const catalog=require('./activeRuntimeArtifacts').artifacts;
 for(const kind of ['zap','fixture'])try{await require('./activeRuntimeArtifacts').verifyImage(adapter,catalog[kind],kind);add(kind+'-image','PASS');}catch(e){add(kind+'-image','BLOCKED',e.code||'IMAGE_UNAVAILABLE');}
 for(const [name,ref] of [['squid',require('./dastGateway').IMAGE],['namespace-helper',require('./dastAcceptanceClient').IMAGE]]){
  try{const [repo,digest]=ref.split('@'),reference=repo.replace(/:[^/:]+$/,'')+'@'+digest;const out=await adapter.run(['image','inspect',reference]);const values=JSON.parse(out.stdout);if(out.exitCode!==0||out.stderr!==''||values.length!==1||values[0].Os!=='linux'||values[0].Architecture!=='amd64'||!values[0].RepoDigests?.includes(reference))throw Error();add(name+'-image','PASS');}catch(_){add(name+'-image','BLOCKED','PINNED_IMAGE_UNAVAILABLE_OR_MISMATCH');}
 }
 try{require('./activeRuntimeArtifacts').assertReady();add('production-capabilities','PASS');}catch(e){add('production-capabilities','BLOCKED',(e.missing||[e.code||'CAPABILITIES_UNVERIFIED']).join(', '));}
 if(context){
  try{await require('./activeDastPrerequisites').check(pool,context);add('operator-execution-staging-baseline','PASS');}catch(e){add('operator-execution-staging-baseline','BLOCKED',e.code||'CONTEXT_UNVERIFIED');}
  try{require('./activeDastPrerequisites').context(context);const rows=(await pool.query('SELECT id FROM active_dast_targets WHERE project_id=$1 AND pipeline_execution_id=$2 AND verified_until>NOW()',[context.projectId,context.executionId])).rows;add('target-enrollment',rows.length===1?'PASS':'BLOCKED');add('in-process-runtime-registration','BLOCKED','MUST_BE_VERIFIED_IN_OWNING_BACKEND_PROCESS');}catch(_){add('target-enrollment','BLOCKED','TARGET_UNVERIFIED');}
 }else add('operator-target-execution-staging','BLOCKED','EXPLICIT_REAL_PROJECT_EXECUTION_OPERATOR_REQUIRED');
 const contract=catalog.zap.capabilities?.verified===true?catalog.zap.capabilities.runtimeContract:null;
 const unknowns=Object.entries({ZAP_APPLICATION_PROXY_TRAFFIC:'zapApplicationProxyVerified',ACTUAL_RATE_ENFORCEMENT:'rateEnforcementVerified',SCAN_COMPLETION:'jobCompletionVerified',SCAN_TIMEOUT:'timeoutVerified',SCAN_CANCELLATION:'cancellationVerified',GENUINE_REDIRECT_CHAIN:'redirectEnforcementVerified'}).filter(([,field])=>contract?.[field]!==true).map(([label])=>label);
 add('scan-dependent-evidence',unknowns.length?'BLOCKED':'PASS',unknowns.length?unknowns.join(', '):undefined);
 return {status:checks.every(c=>c.status==='PASS')?'PASS':'BLOCKED',readOnly:true,scanStarted:false,grantIssued:false,productionReady:false,checks,verifiedConfiguration:catalog.verifiedConfiguration,unverifiedScanDependentCapabilities:unknowns};
}
module.exports={inspect,required};
