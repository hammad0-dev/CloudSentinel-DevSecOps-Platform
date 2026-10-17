'use strict';
// Private command evidence, never a readiness assertion or public log payload.
const fs=require('fs/promises'),path=require('path'),os=require('os'),crypto=require('crypto');
const LIMIT=1048576,EXCERPT=32768,FILE_LIMIT=196608;
const failure=()=>Object.assign(Error('ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED'),{code:'ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED'});
function bounded(text,max){const b=Buffer.from(text);let result=b.subarray(0,max).toString('utf8');while(Buffer.byteLength(result)>max)result=result.slice(0,-1);return result;}
function describe(value,secrets){
 if(typeof value!=='string')return {available:false,type:value===null?'null':typeof value};
 const bytes=Buffer.byteLength(value),complete=bytes<=LIMIT;
 const sha256=crypto.createHash('sha256').update(value).digest('hex');
 if(!complete)return {available:true,bytes,sha256,inputBounded:false,excerpt:null,excerptTruncated:true,classification:'ZAP_AUTOMATION_OUTPUT_OVERSIZED',unknownRecords:null,unrecognized:[],unrecognizedTruncated:true};
 const parse=require('./zapStartupLog').analyze(value),clean=s=>require('./zapStartupEvidence').sanitize(require('./gatewayFailureEvidence').redact(s,secrets),secrets);
 const unknown=parse.records.filter(r=>r.level==='UNKNOWN');
 // Redact each entire value before truncating; retain fingerprints of native bytes.
 return {available:true,bytes,sha256,inputBounded:complete,malformed:parse.malformed,
  excerpt:bounded(clean(value),EXCERPT),excerptTruncated:Buffer.byteLength(clean(value))>EXCERPT,
  classification:complete?parse.failure:'ZAP_AUTOMATION_OUTPUT_OVERSIZED',unknownRecords:complete?parse.unknownRecords:null,
  unrecognized:unknown.slice(0,64).map(r=>({lineNumber:r.lineNumber,sha256:crypto.createHash('sha256').update(r.text).digest('hex'),bytes:Buffer.byteLength(r.text),text:bounded(clean(r.text),512),truncated:Buffer.byteLength(clean(r.text))>512})),unrecognizedTruncated:unknown.length>64};
}
async function save({authorization,diagnosticScope,scannerId,index,output,reason,secrets=[]},{fsImpl=fs,baseDir=os.tmpdir()}={}){
 const context=authorization||diagnosticScope;
 if(authorization&&diagnosticScope||diagnosticScope&&diagnosticScope.scope!=='zap-python-containment'||!context||![context.projectId,context.executionId].every(n=>Number.isSafeInteger(n)&&n>0)||context.projectId===17||!/^([a-f0-9]{64})$/.test(scannerId||'')||![0,1].includes(index)||!/^([A-Z][A-Z0-9_]{0,63})$/.test(reason||''))throw failure();
 const sensitive=[...secrets,...Object.entries(process.env).filter(([k])=>/TOKEN|SECRET|PASS|KEY|AUTH|COOKIE|CREDENTIAL|DATABASE_URL/i.test(k)).map(([,v])=>v)];
 const record={schemaVersion:1,projectId:context.projectId,executionId:context.executionId,...(diagnosticScope?{diagnosticOnly:true,productionReady:false}:{}),scannerId,index,reason,capturedAt:new Date().toISOString(),
  exitCode:Number.isInteger(output?.exitCode)?output.exitCode:null,source:output?.logRead===true?'AUTOMATION_LOG_READ':'AUTOMATION_COMMAND_OUTPUT',captureExitCode:Number.isInteger(output?.captureExitCode)?output.captureExitCode:null,
  streamLayout:output?.streamsCombined===true?'COMBINED_IN_STDOUT':'SEPARATE',stderrSource:output?.logRead===true?'LOG_READ_COMMAND':'AUTOMATION_COMMAND',stdout:describe(output?.stdout,sensitive),stderr:describe(output?.stderr,sensitive)};
 const payload=JSON.stringify(record,null,2);if(Buffer.byteLength(payload)>FILE_LIMIT)throw failure();
 try{
  const directory=await fsImpl.mkdtemp(path.join(baseDir,`cs-zap-automation-p${context.projectId}-e${context.executionId}-`));await fsImpl.chmod(directory,0o700);
  const s=await fsImpl.lstat(directory);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o777)!==0o700)throw failure();
  const file=path.join(directory,'output.json'),h=await fsImpl.open(file,require('fs').constants.O_WRONLY|require('fs').constants.O_CREAT|require('fs').constants.O_EXCL|require('fs').constants.O_NOFOLLOW,0o600);
  try{await h.chmod(0o600);await h.writeFile(payload);}finally{await h.close();}
  return file;
 }catch(_){throw failure();}
}
module.exports={save};
