'use strict';
// Operator-only local CLI: no import, grant, enrollment or scan action exists.
const fs=require('fs/promises'),path=require('path'),os=require('os');
async function saveEvidence(result){
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'cs-zap-containment-evidence-'));
  await fs.chmod(directory,0o700);
  const text=JSON.stringify(result,null,2);
  if(Buffer.byteLength(text)>2097152)throw Object.assign(Error('Oversized diagnostic'),{code:'DIAGNOSTIC_REPORT_OVERSIZED'});
  await fs.writeFile(path.join(directory,'sanitized-report.json'),text,{flag:'wx',mode:0o600});
  return directory;
}
async function run(input){
  if(process.env.DAST_ACTIVE_ENABLED!=='false')throw Object.assign(Error('Active DAST must remain disabled'),{code:'INVALID_DIAGNOSTIC_SCOPE'});
  if(input.activeDiagnostic){require('dotenv').config({path:path.resolve(__dirname,'../.env'),quiet:true});const pool=require('../db');try{input.activePermit=await require('../services/activeDiagnosticAuthorization').issue({pool,sessionFile:input.sessionFile,secret:process.env.JWT_SECRET,input});}finally{await pool.end();}delete input.sessionFile;}
  const {createLifecycle}=require('./dast-acceptance');
  const lifecycle=createLifecycle();
  const {ZapContainmentDiagnostic}=require('../services/zapContainmentDiagnostic');
  const diagnostic=new ZapContainmentDiagnostic({adapter:lifecycle.adapter,lifecycle,input});
  const controller=new AbortController(),cancel=()=>controller.abort();
  process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
  let result;
  try{result=await diagnostic.run({signal:controller.signal});}
  finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
  const directory=await saveEvidence(result);
  return {...result,evidenceDirectory:directory};
}
if(require.main===module){
  const args=process.argv.slice(2),allowed=new Set(['--execute','--scope','--scan','--project','--execution','--ttl','--commissioning-response','--passive-autorun','--active-diagnostic','--session']);
  const values={};let valid=true;
  for(let i=0;i<args.length;i++){
    const name=args[i];if(!allowed.has(name)||Object.hasOwn(values,name)){valid=false;break;}
    if(name==='--execute'||name==='--commissioning-response'||name==='--passive-autorun'||name==='--active-diagnostic')values[name]=true;else values[name]=args[++i];
  }
  const ttl=Number(values['--ttl']);
  if(!valid||values['--execute']!==true||!Number.isInteger(ttl)||ttl<1||ttl>600){process.stderr.write(JSON.stringify({status:'BLOCKED',reason:'EXPLICIT_DIAGNOSTIC_SCOPE_REQUIRED'}));process.exitCode=1;}
  else run({...(values['--active-diagnostic']?{activeDiagnostic:true,sessionFile:values['--session']}:{}),...(values['--commissioning-response']?{commissioningResponse:true}:{}),...(values['--passive-autorun']?{passiveAutorun:true}:{}),scope:values['--scope'],scanId:values['--scan'],projectId:Number(values['--project']),executionId:Number(values['--execution']),expiresAt:Date.now()+ttl*1000}).then(result=>{process.stdout.write(JSON.stringify(result));process.exitCode=result.exitCode;}).catch(error=>{process.stderr.write(JSON.stringify({status:'BLOCKED',reason:/^[A-Z_]{1,64}$/.test(error.code||'')?error.code:'DIAGNOSTIC_FAILED',fullContainment:false,containmentReady:false}));process.exitCode=1;});
}
module.exports={run,saveEvidence};
