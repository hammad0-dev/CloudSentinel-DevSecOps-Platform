'use strict';
const fs=require('fs/promises'),path=require('path'),crypto=require('crypto');
const fail=code=>Object.assign(new Error(code),{code,nonRetryable:true});
const DRIVER=path.resolve(__dirname,'../scripts/zap_commissioning_probe.py');
const FILE='commissioning-probe.py';
function command(scannerId,mode,input){
 const json=JSON.stringify(input),chunks=json.match(/.{1,384}/gs)||[];
 return ['exec',scannerId,'python3','-I',`/zap/wrk/${FILE}`,mode,...chunks];
}
// Diagnostic comparisons only: these never establish request equivalence.
function requestDifference(actual,expected){
 const parse=value=>{
  if(typeof value!=='string'||Buffer.byteLength(value)>16384)return null;
  const lines=value.split('\r\n');
  if(lines.length!==5||lines[3]!==''||lines[4]!==''||lines.some(l=>/[\r\n\0]/.test(l)))return null;
  const first=/^(GET) (http:\/\/([a-z0-9-]+\.test):([0-9]+)(\/[^ ]*)) (HTTP\/1\.1)$/.exec(lines[0]);
  if(!first)return null;
  const headers=lines.slice(1,3).map(line=>/^([A-Za-z-]+): ([^\r\n]*)$/.exec(line));
  if(headers.some(h=>!h)||new Set(headers.map(h=>h[1].toLowerCase())).size!==2||headers.some(h=>!['host','connection'].includes(h[1].toLowerCase())))return null;
  const fields=Object.fromEntries(headers.map(h=>[h[1].toLowerCase(),h[2]]));
  return {method:first[1],target:first[2],scheme:'http',host:first[3],port:first[4],pathQuery:first[5],version:first[6],fields,names:headers.map(h=>h[1]),order:headers.map(h=>h[1].toLowerCase())};
 };
 const a=parse(actual),e=parse(expected),result={actualStructured:!!a,expectedStructured:!!e};
 if(typeof actual==='string'&&typeof expected==='string'){
  const left=Buffer.from(actual),right=Buffer.from(expected),offsets=[];
  for(let i=0;i<Math.max(left.length,right.length)&&offsets.length<64;i++)if(left[i]!==right[i])offsets.push(i);
  result.firstDifferingByteOffsets=offsets;result.offsetLimit=64;
 }
 if(a&&e){
  result.matches=Object.fromEntries(['method','target','scheme','host','port','pathQuery','version'].map(k=>[k,a[k]===e[k]]));
  result.matches.hostHeader=a.fields.host===e.fields.host;result.matches.connectionHeader=a.fields.connection===e.fields.connection;
  result.headerNamesExact=JSON.stringify(a.names)===JSON.stringify(e.names);result.headerOrderExact=JSON.stringify(a.order)===JSON.stringify(e.order);
  result.headerNameCaseOnly=JSON.stringify(a.order)===JSON.stringify(e.order)&&!result.headerNamesExact&&Object.values(result.matches).every(Boolean);
 }
 return result;
}
// The retained same-transaction diagnostic proved only Host -> host casing.
// Compare every other byte exactly; no destination, header value or body rewrite.
function requestMatches(actual,expected){
 if(actual===expected)return true;
 const difference=requestDifference(actual,expected);
 return difference.headerNameCaseOnly===true&&actual===expected.replace('\r\nHost:', '\r\nhost:');
}
function response(value,request,body){
 const messages=value?.sendRequest;
 const m=Array.isArray(messages)&&messages.length===1?messages[0]:null,header=m?.responseHeader;
 const predicates={singleMessage:Array.isArray(messages)&&messages.length===1,messageObject:!!m&&typeof m==='object',
  requestMatches:requestMatches(m?.requestHeader,request),requestBodyEmpty:m?.requestBody===undefined||m?.requestBody==='',headerPresent:typeof header==='string',headerBounded:typeof header==='string'&&Buffer.byteLength(header)<=16384,
  status200:typeof header==='string'&&/^HTTP\/1\.[01] 200(?: |\r?$)/m.test(header),
  squidVia:typeof header==='string'&&/^Via:\s*[^\r\n]*squid[^\r\n]*$/im.test(header),
  noRedirect:typeof header==='string'&&!/^Location:/im.test(header),bodyMatches:m?.responseBody===body};
 if(Object.values(predicates).some(v=>!v)){
  const error=fail('COMMISSIONING_RESPONSE_BLOCKED');
  const shape=v=>typeof v==='string'?{type:'string',bytes:Buffer.byteLength(v),sha256:crypto.createHash('sha256').update(v).digest('hex')}:{type:v===null?'null':typeof v};
  error.responseDiagnostic={predicates,failedPredicates:Object.keys(predicates).filter(k=>!predicates[k]),messageCount:Array.isArray(messages)?messages.length:null,
   request:shape(m?.requestHeader),expectedRequest:shape(request),header:shape(header),body:shape(m?.responseBody),expectedBody:shape(body),
   statusLineCategory:typeof header==='string'&&/^HTTP\/1\.[01] \d{3}(?: |\r?$)/m.test(header)?header.match(/^HTTP\/1\.[01] (\d{3})/m)[1]:'MISSING_OR_MALFORMED',
   requestDifference:requestDifference(m?.requestHeader,request)};
  throw error;
 }
 return true;
}
function correlate(text,{nonce,clientIp,hostname}){
 if(typeof text!=='string'||Buffer.byteLength(text)>1048576)throw fail('COMMISSIONING_PROXY_LOG_BLOCKED');
 const rows=text.split('\n').filter(line=>line.includes(`cs_commission=${nonce}-`));
 if(rows.length!==2)throw fail('COMMISSIONING_PROXY_CORRELATION_BLOCKED');
 return rows.map((line,i)=>{
  const fields=line.trim().split(/\s+/),route=i===0?'sqli?id=1':'xss?q=hello';
  if(fields.length!==6||!/^\d+\.\d{3}$/.test(fields[0])||fields[1]!==clientIp||fields[2]!=='GET'||
    fields[3]!==`http://${hostname}:18080/test/${route}&cs_commission=${nonce}-${i}`||fields[4]!=='200'||
    !/^TCP_(?:MISS|MEM_HIT|HIT)\/HIER_DIRECT$/.test(fields[5]))throw fail('COMMISSIONING_PROXY_CORRELATION_BLOCKED');
  return {timestamp:Number(fields[0]),clientIp,method:'GET',status:200,path:'/test/'+route.split('?')[0]};
 });
}
async function stage(directory,files){const bytes=await fs.readFile(DRIVER);await fs.writeFile(path.join(directory,FILE),bytes,{flag:'wx',mode:0o400});files.set(FILE,crypto.createHash('sha256').update(bytes).digest('hex'));}
async function collect({adapter,scannerId,gatewayId,clientIp,authorization,apiKey,proxy,requirePassive=false,verify,signal}){
 const check=()=>{if(signal?.aborted)throw fail('ACTIVE_CANCELLED');require('./activeDastCommissioning').validate(authorization,authorization);if(!require('./activeDastCommissioning').runtimeAllowed(authorization))throw fail('COMMISSIONING_RUNTIME_BLOCKED');};
 async function execute(mode,input){check();const out=await adapter.run(command(scannerId,mode,input));check();if(out.exitCode!==0||out.stderr||Buffer.byteLength(out.stdout)>1572864)throw fail('COMMISSIONING_DRIVER_BLOCKED');const parsed=JSON.parse(out.stdout);if(parsed.error)throw fail('COMMISSIONING_DRIVER_BLOCKED');return parsed;}
 const writable=require('../config/zap-writable-paths.json');
 const args=['zap.sh','-silent','-daemon','-host','127.0.0.1','-port','8090','-dir','/home/zap/.ZAP','-config',writable.callbackBinding,'-config','api.disablekey=false','-config',`api.key=${apiKey}`,
  '-config','autoupdate.checkOnStart=false','-config','autoupdate.downloadNewRelease=false','-config','autoupdate.installAddonUpdates=false',
  '-config','connection.proxyChain.enabled=true','-config',`connection.proxyChain.hostName=${new URL(proxy).hostname}`,'-config','connection.proxyChain.port=3128'];
 await verify();await execute('start',args);const deadline=Date.now()+180000;let initialized=false;
 while(Date.now()<deadline){check();try{const v=await execute('views',{key:apiKey});require('./zapContainmentDiagnostic').daemonViews(v.version,v.addons,v.rules);
  if(requirePassive){const loaded=v.addons.installedAddons.filter(a=>a.id==='pscan');if(loaded.length!==1||loaded[0].version!=='0.6.0'||loaded[0].installationStatus!=='INSTALLED')throw fail('COMMISSIONING_PASSIVE_RUNTIME_BLOCKED');}
  initialized=true;break;}catch(error){if(signal?.aborted)throw fail('ACTIVE_CANCELLED');if(['COMMISSIONING_AUTHORIZATION_BLOCKED','COMMISSIONING_PASSIVE_RUNTIME_BLOCKED'].includes(error.code))throw error;}await new Promise(resolve=>setTimeout(resolve,250));}
 if(!initialized)throw fail('COMMISSIONING_INITIALIZATION_BLOCKED');
 const logs=await execute('log',{}),analysis=require('./zapStartupLog').analyze(logs.log);
 if(analysis.failure||!logs.bytes||!/Extensions loaded/.test(logs.log)||!/ZAP is now listening on 127\.0\.0\.1:8090/.test(logs.log))throw fail('COMMISSIONING_INITIALIZATION_BLOCKED');
 await verify();
 const readiness=await adapter.run(['exec',scannerId,...require('./zapStartupEvidence').READINESS_ARGS]);
 if(readiness.exitCode!==0||readiness.stderr||Buffer.byteLength(readiness.stdout)>524288)throw fail('COMMISSIONING_INITIALIZATION_BLOCKED');
 const positive=JSON.parse(readiness.stdout);
 if(!Array.isArray(positive.writable)||positive.writable.length!==4||positive.writable.some(x=>x!==true)||positive.policy?.xmlParsed!==true||!Number.isSafeInteger(positive.policy.bytes)||positive.policy.bytes<1||positive.policy.bytes>65536||!/^[a-f0-9]{64}$/.test(positive.policy.sha256||''))throw fail('COMMISSIONING_INITIALIZATION_BLOCKED');
 for(const [name,family,protocol] of [['tcp',4,'tcp'],['tcp6',6,'tcp'],['udp',4,'udp'],['udp6',6,'udp']])require('./zapContainmentDiagnostic').listeners(positive.tables?.[name],family,protocol);
 const configuration=await execute('configure',{key:apiKey,hostname:authorization.hostname});
 if(configuration.rateConfigured!==2||configuration.concurrencyConfigured!==1)throw fail('COMMISSIONING_CONFIGURATION_BLOCKED');
 const auth=await execute('authentication',{key:apiKey}),authLog=await execute('log',{});
 if(auth.before?.version!=='2.17.0'||auth.after?.version!=='2.17.0'||!Array.isArray(auth.rejections)||auth.rejections.length!==2||auth.rejections.some(x=>x.rejected!==true))throw fail('COMMISSIONING_AUTHENTICATION_BLOCKED');
 const newLogs=authLog.log.slice(logs.log.length);
 if(!authLog.log.startsWith(logs.log)||(newLogs.match(/(?:API key|apikey)[^\r\n]*(?:invalid|missing|incorrect)|(?:invalid|missing|incorrect)[^\r\n]*(?:API key|apikey)/gi)||[]).length<2)throw fail('COMMISSIONING_AUTHENTICATION_BLOCKED');
 const nonce=crypto.randomBytes(16).toString('hex'),results=[];
 for(let i=0;i<2;i++){
  check();const route=i===0?'sqli?id=1':'xss?q=hello',request=`GET http://${authorization.hostname}:18080/test/${route}&cs_commission=${nonce}-${i} HTTP/1.1\r\nHost: ${authorization.hostname}:18080\r\nConnection: close\r\n\r\n`;
  const started=Date.now(),value=await execute('request',{key:apiKey,request});
  try{response(value,request,i===0?'[["demo-one"]]':'<html><body>fixture: hello</body></html>');}
  catch(error){
   if(error.code==='COMMISSIONING_RESPONSE_BLOCKED'){
    let access;
    try{access=await adapter.run(['exec',gatewayId,'cat','/tmp/cloudsentinel-active-access.log']);}catch(_){access=null;}
    try{error.responseEvidenceFile=await require('./commissioningResponseEvidence').save({authorization,scannerId,gatewayId,proxy,index:i,diagnostic:error.responseDiagnostic,access,secrets:[apiKey]});}
    catch(_){error.responseEvidenceError='COMMISSIONING_RESPONSE_EVIDENCE_WRITE_FAILED';}
   }
   throw error;
  }
  results.push({path:i===0?'/test/sqli':'/test/xss',status:200,durationMs:Date.now()-started});
  if(i===0)await new Promise(resolve=>setTimeout(resolve,500));
 }
 const out=await adapter.run(['exec',gatewayId,'cat','/tmp/cloudsentinel-active-access.log']);
 if(out.exitCode!==0||out.stderr)throw fail('COMMISSIONING_PROXY_LOG_BLOCKED');
 const connections=correlate(out.stdout,{nonce,clientIp,hostname:authorization.hostname});
 await verify();await execute('stop',{key:apiKey});
 // A shutdown response is not process-exit evidence. Require the API to stop
 // listening before autorun may open the same port and home directory.
 const until=Date.now()+10000;let stopped=false;
 while(Date.now()<until){check();if((await execute('stopped',{})).stopped===true){stopped=true;break;}await new Promise(resolve=>setTimeout(resolve,250));}
 if(!stopped)throw fail('COMMISSIONING_DAEMON_STOP_BLOCKED');
 await verify();return {verified:true,source:'ZAP_AUTHENTICATED_SEND_REQUEST_AND_SQUID_ACCESS_LOG',results,connections,configuration,observedSpacingMs:Math.round((connections[1].timestamp-connections[0].timestamp)*1000),rateEnforcement:'UNVERIFIED',redirectFollowing:false};
}
async function executePlan({adapter,scannerId,gatewayId,index,args,authorization,diagnosticPermit,verify,signal}){
 if(![0,1].includes(index)||!Array.isArray(args)||args[0]==='zap.sh'||args.at(-1)!==`/zap/wrk/plan-${index}.yaml`)throw fail('COMMISSIONING_PLAN_BLOCKED');
 const log=`/tmp/commissioning-plan-${index}.log`,exit=`/tmp/commissioning-plan-${index}.exit`;
 const diagnostic=diagnosticPermit?require('./zapContainmentDiagnostic').claimPassivePlanPermit(diagnosticPermit,{scannerId,gatewayId,index,args}):null;
 if(diagnostic&&authorization)throw fail('DIAGNOSTIC_ACTION_FORBIDDEN');
 const check=()=>{if(signal?.aborted)throw fail('ACTIVE_CANCELLED');if(diagnostic){require('./zapContainmentDiagnostic').verifyPassivePlanPermit(diagnosticPermit,{scannerId,gatewayId,index,args});return;}require('./module2ActiveDast').validateAuthorization(authorization,authorization);if(!require('./activeDastCommissioning').runtimeAllowed(authorization))throw fail('COMMISSIONING_RUNTIME_BLOCKED');};
 let lastOutput,processExitCode=null;
 const phaseBudget=diagnostic?.activeDiagnostic?require('./zapDiagnosticBudget').create({expiresAt:diagnostic.expiresAt}):null;
 const bounded=fn=>phaseBudget?phaseBudget.run(fn):fn();
 try{
 check();await bounded(verify);
 const started=await adapter.run(['exec','-d',scannerId,'/bin/sh','-c',`zap.sh "$@" >${log} 2>&1; cs_status=$?; printf '%s\\n' "$cs_status" >${exit}`,'commissioning-plan',...args]);
 if(started.exitCode!==0||started.stderr)throw fail('COMMISSIONING_PLAN_BLOCKED');
 // No 30-second Docker exec is left blocking behind cancellation. Poll only
 // fixed owned files; absence of the completion marker is never completion.
 while(Date.now()<(diagnostic||authorization).expiresAt){
  check();phaseBudget?.check();await bounded(verify);let status;
  if(phaseBudget){const progress=await phaseBudget.run(()=>adapter.run(['exec',scannerId,'cat',log]));if(progress.exitCode!==0||progress.stderr||Buffer.byteLength(progress.stdout)>1048576)throw fail('DIAGNOSTIC_PROGRESS_UNVERIFIED');lastOutput=progress;phaseBudget.observe(progress.stdout);}
  const access=await bounded(()=>adapter.run(['exec',gatewayId,'cat','/tmp/cloudsentinel-active-access.log']));
  if(access.exitCode!==0||access.stderr||Buffer.byteLength(access.stdout)>1048576)throw fail('COMMISSIONING_REQUEST_BUDGET_BLOCKED');
  if(access.stdout.trim().split('\n').filter(Boolean).length>600)throw fail('COMMISSIONING_REQUEST_BUDGET_EXCEEDED');
  try{status=await bounded(()=>adapter.run(['exec',scannerId,'cat',exit]));}catch(error){if(error.code!=='MISSING_RESOURCE')throw error;}
  if(status){
   if(status.exitCode!==0||status.stderr||!/^\d{1,3}\n$/.test(status.stdout)||Number(status.stdout)>255)throw fail('COMMISSIONING_PLAN_BLOCKED');
   processExitCode=Number(status.stdout);
   const output=await adapter.run(['exec',scannerId,'cat',log]);lastOutput=output;
   if(output.exitCode!==0||output.stderr||Buffer.byteLength(output.stdout)>1048576)throw fail('COMMISSIONING_PLAN_BLOCKED');
   phaseBudget?.observe(output.stdout);phaseBudget?.complete();
   return {exitCode:Number(status.stdout),stdout:output.stdout,stderr:'',streamsCombined:true,...(phaseBudget?{diagnosticBudget:phaseBudget}:{})};
  }
  await new Promise(resolve=>setTimeout(resolve,500));
 }
 throw fail('ACTIVE_TIMED_OUT');
 }catch(error){
  // Preserve failed/partial native output while the owned container still exists.
  // Fresh ownership verification is required before any additional log read.
  try{
   await verify();
   const output=lastOutput||await adapter.run(['exec',scannerId,'cat',log]);
   const keyArgs=args.filter(a=>a.startsWith('api.key=')).map(a=>a.slice(8));
   error.automationEvidenceFile=await require('./zapAutomationEvidence').save({...(diagnostic?{diagnosticScope:diagnostic}:{authorization}),scannerId,index,output:{...output,exitCode:processExitCode,captureExitCode:output.exitCode,logRead:true,streamsCombined:true},reason:/^[A-Z][A-Z0-9_]{0,63}$/.test(error.code||'')?error.code:'COMMISSIONING_PLAN_BLOCKED',secrets:keyArgs});
  }catch(_){error.automationEvidenceError='ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED';}
  throw error;
 }
}
module.exports={stage,collect,command,response,correlate,executePlan,requestDifference};
