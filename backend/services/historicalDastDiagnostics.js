'use strict';
const fs=require('fs/promises'),constants=require('fs').constants,path=require('path'),crypto=require('crypto');
const catalog=require('../config/historical-dast-diagnostics.json');
const fail=(code,status=503)=>Object.assign(Error(code),{code,status});
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
async function read(directory,name){
 if(path.basename(name)!==name)throw fail('DIAGNOSTIC_EVIDENCE_INVALID');
 const h=await fs.open(path.join(directory,name),constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const s=await h.stat();if(!s.isFile()||s.uid!==process.getuid()||(s.mode&511)!==384||s.size>2097152)throw fail('DIAGNOSTIC_EVIDENCE_INVALID');return await h.readFile();}finally{await h.close();}
}
async function load(entry){
 try{
 const s=await fs.lstat(entry.directory);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&511)!==448)throw fail('DIAGNOSTIC_EVIDENCE_INVALID');
 const mb=await read(entry.directory,'manifest.json'),rb=await read(entry.directory,'sanitized-report.json');if(hash(mb)!==entry.manifestSha256||hash(rb)!==entry.resultSha256)throw fail('DIAGNOSTIC_EVIDENCE_INTEGRITY_FAILED');
 const manifest=JSON.parse(mb),result=JSON.parse(rb),artifacts={};
 for(const name of ['automation','report','alerts','identity','requests']){const a=manifest.artifacts?.[name];if(a?.state!=='RETAINED_SANITIZED')throw fail('DIAGNOSTIC_EVIDENCE_INVALID');const bytes=await read(entry.directory,a.file);if(hash(bytes)!==a.storedSha256)throw fail('DIAGNOSTIC_EVIDENCE_INTEGRITY_FAILED');artifacts[name]=JSON.parse(bytes);}
 const {identity,report,automation,alerts}=artifacts;
 if(manifest.projectId!==entry.projectId||manifest.diagnosticOnly!==true||manifest.productionReady!==false||identity.diagnosticId!==entry.diagnosticId||identity.diagnosticOnly!==true||identity.productionReady!==false||result.scope?.scanId!==entry.diagnosticId||result.scope?.projectId!==entry.projectId||result.status!=='PASS'||!result.cleanup?.cleaned||result.cleanup.residual?.length||!result.activeAutomation?.completed||result.activeAutomation.activeScanJobs!==1||automation.exitCode!==0||!/^Automation plan succeeded!$/m.test(automation.stdout)||!/^Job activeScan finished, time taken: /m.test(automation.stdout))throw fail('DIAGNOSTIC_COMPLETION_UNVERIFIED');
 if(!Array.isArray(report.site)||report.site.length!==1||report.site[0]['@name']!==`http://${entry.diagnosticId}.test:18080`||JSON.stringify(report.site.flatMap(s=>s.alerts||[]))!==JSON.stringify(alerts))throw fail('DIAGNOSTIC_REPORT_INVALID');
 const approved=new Set(['40012','40014','40016','40017','40018','40019','40020']);
 const findings=alerts.map(a=>{if(!/^[0-9]+$/.test(String(a.pluginid))||!Array.isArray(a.instances)||!a.instances.length||!['0','1','2','3'].includes(String(a.riskcode)))throw fail('DIAGNOSTIC_REPORT_INVALID');const endpoints=[...new Set(a.instances.map(i=>{const u=new URL(i.uri);if(u.origin!==report.site[0]['@name']||!['/test/sqli','/test/xss'].includes(u.pathname)||u.username||u.password||u.hash)throw fail('DIAGNOSTIC_REPORT_SCOPE_INVALID');return u.pathname;}))];return {name:String(a.name).slice(0,256),ruleId:String(a.pluginid),cwe:/^[0-9]+$/.test(String(a.cweid))?`CWE-${a.cweid}`:null,severity:['INFORMATIONAL','LOW','MEDIUM','HIGH'][Number(a.riskcode)],source:approved.has(String(a.pluginid))?'ACTIVE':'PASSIVE',endpoints,instanceCount:a.instances.length};});
 const total=findings.reduce((n,f)=>n+f.instanceCount,0);if(total!==result.activeAutomation.findingCount)throw fail('DIAGNOSTIC_REPORT_INVALID');
 return {diagnosticId:entry.diagnosticId,projectId:entry.projectId,pipelineExecutionId:null,label:'Historical Isolated Active DAST Diagnostic — Not Part of Execution #37',target:'Disposable isolated Python fixture only; not Project 17',date:manifest.capturedAt,diagnosticStatus:result.status,evidenceStatus:manifest.state,productionAcceptance:manifest.acceptance,integrity:'VERIFIED',configuredRequestsPerSecond:2,measuredRateEnforcement:manifest.rate.state,originalReportSha256:manifest.artifacts.report.originalSha256,storedReportSha256:manifest.artifacts.report.storedSha256,totalFindings:total,findings};
 }catch(e){if(e.code?.startsWith('DIAGNOSTIC_'))throw e;throw fail('DIAGNOSTIC_EVIDENCE_UNAVAILABLE');}
}
async function get(pool,user,projectId){
 if(user?.pipelineOrchestrator||!Number.isSafeInteger(user?.id))throw fail('OWNER_AUTHENTICATION_REQUIRED',403);
 if(!Number.isSafeInteger(projectId)||projectId<1)throw fail('INVALID_PROJECT',400);
 if((await pool.query('SELECT id FROM projects WHERE id=$1 AND user_id=$2',[projectId,user.id])).rows.length!==1)throw fail('PROJECT_NOT_FOUND',404);
 return {diagnostics:await Promise.all(catalog.filter(e=>e.projectId===projectId).map(load))};
}
module.exports={get,load};
