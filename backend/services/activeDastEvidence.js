'use strict';
const fs=require('fs/promises'),os=require('os'),path=require('path'),crypto=require('crypto');
const LIMIT=2*1024*1024;
const digest=v=>crypto.createHash('sha256').update(v).digest('hex');
function clean(value,secrets=[]){
 if(Array.isArray(value))return value.map(v=>clean(v,secrets));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,/body|payload|attack|cookie|token|secret|password|authorization|header/i.test(k)?'[REDACTED]':clean(v,secrets)]));
 if(typeof value==='string')return require('./gatewayFailureEvidence').redact(value,secrets).replace(/(https?:\/\/[^\s?#]+)[?#][^\s]*/g,'$1?[REDACTED]');
 return value;
}
function requests(text,{clientIp,hostname}){
 if(typeof text!=='string'||Buffer.byteLength(text)>LIMIT)return {state:'MISSING_OR_OVERSIZED',records:[],rate:{state:'UNVERIFIED'}};
 const records=[];let invalid=0;
 for(const line of text.split('\n').filter(Boolean)){
  const f=line.trim().split(/\s+/);let u;try{u=new URL(f[3]);}catch{invalid++;continue;}
  if(f.length!==6||!/^\d+\.\d{3}$/.test(f[0])||f[1]!==clientIp||u.hostname!==hostname||u.port!=='18080'||!['/test/sqli','/test/xss'].includes(u.pathname)||!/^\d{3}$/.test(f[4])){invalid++;continue;}
  records.push({completedAtMs:Number(f[0])*1000,method:/^[A-Z]{1,12}$/.test(f[2])?f[2]:'INVALID',path:u.pathname,status:Number(f[4]),gatewayResult:f[5].replace(/[^A-Z_/]/g,'').slice(0,64)});
 }
 const times=records.map(x=>x.completedAtMs).sort((a,b)=>a-b);let max=0;for(let i=0,j=0;i<times.length;i++){while(times[i]-times[j]>=1000)j++;max=Math.max(max,i-j+1);}
 return {state:invalid?'UNCORRELATED':records.length?'CORRELATED_COMPLETIONS':'MISSING',invalidRecords:invalid,count:records.length,records,originAttribution:'SHARED_SCANNER_NAMESPACE_ONLY',scope:'OWNED_LIFECYCLE_COMPLETIONS_INCLUDES_PASSIVE_AND_VERIFICATION_TRAFFIC',zapOriginVerified:false,rate:{state:'UNVERIFIED',configuredRequestsPerSecond:2,intervalMs:1000,maxObservedCompletionsPerInterval:max,observedCompletionBurst:max>2,limitation:'Squid %ts/%tu timestamps record transaction completion, not ZAP dispatch/enforcement intervals. Completion bursts cannot prove or disprove dispatch rate enforcement.'}};
}
async function save(record,{baseDir=os.tmpdir(),secrets=[]}={}){
 if(!Number.isSafeInteger(record.projectId)||record.projectId===17||!Number.isSafeInteger(record.executionId))throw Error('ACTIVE_EVIDENCE_IDENTITY');
 const directory=await fs.mkdtemp(path.join(baseDir,`cs-active-evidence-p${record.projectId}-e${record.executionId}-`));await fs.chmod(directory,0o700);
 const sensitive=[...secrets,...Object.entries(process.env).filter(([k])=>/TOKEN|SECRET|PASS|KEY|AUTH|COOKIE|CREDENTIAL|DATABASE_URL/i.test(k)).map(([,v])=>v)];
 const manifest={schemaVersion:1,projectId:record.projectId,...(record.diagnosticOnly===true?{diagnosticOnly:true,productionReady:false,executionReferenceId:record.executionId}:{executionId:record.executionId}),state:'COMPLETE',capturedAt:new Date().toISOString(),artifacts:{},rate:record.requests?.rate||{state:'UNVERIFIED'},limitations:[]};
 for(const [name,value] of Object.entries(record.artifacts||{})){
  if(!/^[a-z-]+$/.test(name))throw Error('ACTIVE_EVIDENCE_NAME');
  const raw=typeof value==='string'?value:JSON.stringify(value);if(value===null||value===undefined||typeof raw!=='string'||Buffer.byteLength(raw)>LIMIT){manifest.state='INCOMPLETE';manifest.artifacts[name]={state:'MISSING_OR_OVERSIZED'};continue;}
  let content=value;if(name==='report'&&typeof value==='string'){try{content=JSON.parse(value);if(!Array.isArray(content.site))throw Error('INVALID_REPORT');}catch(_){manifest.state='INCOMPLETE';manifest.artifacts[name]={state:'MALFORMED'};continue;}}
  const payload=JSON.stringify(clean(content,sensitive),null,2);const file=path.join(directory,name+'.json'),tmp=file+'.tmp';const h=await fs.open(tmp,'wx',0o600);try{await h.writeFile(payload);await h.sync();}finally{await h.close();}await fs.rename(tmp,file);
  manifest.artifacts[name]={state:'RETAINED_SANITIZED',originalSha256:digest(raw),storedSha256:digest(payload),bytes:Buffer.byteLength(raw),file:path.basename(file)};
 }
 if(record.requests?.state!=='CORRELATED_COMPLETIONS'||record.requests?.zapOriginVerified!==true)manifest.state='INCOMPLETE';
 if(!Number.isInteger(record.artifacts?.automation?.exitCode)||typeof record.artifacts?.automation?.stdout!=='string')manifest.state='INCOMPLETE';
 for(const required of ['automation','report','alerts','identity','requests'])if(!manifest.artifacts[required]||manifest.artifacts[required].state!=='RETAINED_SANITIZED')manifest.state='INCOMPLETE';
 manifest.acceptance=manifest.state==='COMPLETE'&&manifest.rate.state==='VERIFIED'?'PASS':'BLOCKED';
 const file=path.join(directory,'manifest.json'),tmp=file+'.tmp';const h=await fs.open(tmp,'wx',0o600);try{await h.writeFile(JSON.stringify(manifest,null,2));await h.sync();}finally{await h.close();}await fs.rename(tmp,file);return {file,state:manifest.state,acceptance:manifest.acceptance};
}
module.exports={save,requests,clean};
