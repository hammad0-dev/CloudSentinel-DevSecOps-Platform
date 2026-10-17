'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const traffic=require('../services/zapCommissioningTraffic');
const rules=require('../config/zap-active-policy-v1.json').approvedPluginIds;
const header='  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n';
function setup(t,scenario='ok'){
 const keys=['DAST_ACTIVE_COMMISSIONING_ENABLED','DAST_ACTIVE_COMMISSIONING_CONTEXT','DAST_ACTIVE_ENABLED','DAST_ACTIVE_COMMISSIONING_PHASE','DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT'];const old=keys.map(k=>process.env[k]);t.after(()=>keys.forEach((k,i)=>{if(old[i]===undefined)delete process.env[k];else process.env[k]=old[i];}));
 const ctx={projectId:42,executionId:100,userId:7};process.env.DAST_ACTIVE_COMMISSIONING_ENABLED='true';process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT=JSON.stringify({...ctx,expiresAt:Date.now()+600000});process.env.DAST_ACTIVE_ENABLED='true';process.env.DAST_ACTIVE_COMMISSIONING_PHASE='ACTIVE_COMMISSIONING';process.env.DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT=JSON.stringify({...ctx,expiresAt:Date.now()+240000});
 const c=require('../services/activeRuntimeArtifacts').artifacts;
 const authorization={...ctx,...require('../services/activeDastCommissioning').bind(ctx,c),gatewayContainerId:'f'.repeat(64),fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:c.zap.imageId};
 const calls=[],logs=[];let requests=0,authenticated=false;
 const adapter={async run(args){calls.push(args);let result;
  if(args[1]==='gateway')return {exitCode:0,stderr:'',stdout:logs.join('\n')};
  if(args.includes('/zap/wrk/commissioning-probe.py')){
   const mode=args[5],input=JSON.parse(args.slice(6).join(''));
   if(mode==='start')result={started:true,pid:100};
   if(mode==='views')result={version:{version:'2.17.0'},addons:{installedAddons:Object.entries(require('../services/zapInitialization').expectedAddons).map(([id,version])=>({id,version,installationStatus:'INSTALLED'}))},rules:{scanners:rules.map(id=>({id}))}};
   if(mode==='log')result={bytes:200,log:'100 [ZAP-daemon] INFO org.zaproxy.ZAP - Extensions loaded\n200 [ZAP-daemon] INFO org.zaproxy.ZAP - ZAP is now listening on 127.0.0.1:8090\n'+(authenticated?'300 [ZAP-daemon] WARN org.zaproxy.API - API key missing\n301 [ZAP-daemon] WARN org.zaproxy.API - API key incorrect\n':'')};
   if(mode==='authentication'){authenticated=true;result={before:{version:'2.17.0'},after:{version:'2.17.0'},rejections:[{rejected:true},{rejected:true}]};}
   if(mode==='configure')result={rateConfigured:2,concurrencyConfigured:1};
   if(mode==='request'){
    const url=input.request.split(' ')[1],i=requests++;
    logs.push(`${1700000000+i}.000 ${scenario==='wrong-peer'?'172.30.1.99':'172.30.1.3'} GET ${url} 200 TCP_MISS/HIER_DIRECT`);
    result={sendRequest:[{requestHeader:input.request,responseHeader:'HTTP/1.1 200 OK\r\nVia: 1.1 fixture-proxy (squid/6.6)\r\n\r\n',responseBody:i===0?'[["demo-one"]]':'<html><body>fixture: hello</body></html>'}]};
    if(scenario==='redirect')result.sendRequest[0].responseHeader='HTTP/1.1 302 Found\r\nLocation: http://external.test\r\n';
   }
   if(mode==='stop')result={Result:'OK'};
   if(mode==='stopped')result={stopped:true};
  }else{
   result={writable:scenario==='readonly'?[false,true,true,true]:[true,true,true,true],policy:{xmlParsed:true,bytes:100,sha256:'b'.repeat(64)},tables:{tcp:header+'0: 0100007F:1F9A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 111\n',tcp6:header,udp:header,udp6:header}};
  }
  if(!result)throw Error('Unexpected mocked operation');return {exitCode:0,stderr:'',stdout:JSON.stringify(result)};
 }};
 return {adapter,authorization,calls,get requests(){return requests;}};
}
test('fixed driver arguments fit the Docker allowlist and contain no shell execution',()=>{
 const args=traffic.command('a'.repeat(64),'request',{request:'x'.repeat(2048)});assert.ok(args.every(a=>a.length<512));assert.ok(!args.includes('/bin/sh'));assert.equal(args[4],'/zap/wrk/commissioning-probe.py');
});
test('authenticated ZAP response and same-transaction Squid records correlate two benign requests',async t=>{
 const d=setup(t);let verified=0;const result=await traffic.collect({...d,scannerId:'scanner',gatewayId:'gateway',clientIp:'172.30.1.3',apiKey:'private-key',proxy:'http://172.30.1.4:3128',verify:async()=>{verified++;}});
 assert.equal(result.verified,true);assert.equal(d.requests,2);assert.ok(verified>=3);assert.equal(result.rateEnforcement,'UNVERIFIED');assert.equal(result.connections.length,2);assert.equal(JSON.stringify(result).includes('private-key'),false);
 const modes=d.calls.filter(a=>a[4]==='/zap/wrk/commissioning-probe.py').map(a=>a[5]);assert.ok(modes.indexOf('configure')<modes.indexOf('request'));assert.equal(modes.at(-1),'stopped');
});
for(const scenario of ['wrong-peer','redirect','readonly'])test('traffic collector fails closed for '+scenario,async t=>{
 const d=setup(t,scenario);await assert.rejects(traffic.collect({...d,scannerId:'scanner',gatewayId:'gateway',clientIp:'172.30.1.3',apiKey:'private-key',proxy:'http://172.30.1.4:3128',verify:async()=>{}}));
 if(scenario==='readonly')assert.equal(d.requests,0);
});
test('namespace/ownership verification failure prevents all application commands',async t=>{
 const d=setup(t);await assert.rejects(traffic.collect({...d,scannerId:'scanner',verify:async()=>{throw Error('ownership');}}));assert.equal(d.calls.length,0);
});
test('missing or duplicate proxy records and contradictory responses are rejected',()=>{
 const input={nonce:'a'.repeat(32),clientIp:'172.30.1.3',hostname:'fixture.test'};for(const text of ['', 'malformed', `1700000000.000 172.30.1.3 GET http://fixture.test/ 200 TCP_MISS/HIER_DIRECT`])assert.throws(()=>traffic.correlate(text,input));
 for(const value of [{},{sendRequest:[]},{sendRequest:[{requestHeader:'expected',responseHeader:'HTTP/1.1 200 OK\r\n',responseBody:'body'}]}])assert.throws(()=>traffic.response(value,'expected','body'));
});
test('response predicate diagnostics identify every rejection without retaining native secrets',()=>{
 const request='GET http://fixture.test:18080/test/sqli?id=1 HTTP/1.1\r\nHost: fixture.test:18080\r\n\r\n',body='[["demo-one"]]';
 const valid={requestHeader:request,responseHeader:'HTTP/1.1 200 OK\r\nVia: 1.1 gateway (squid/6.6)\r\n\r\n',responseBody:body};
 assert.equal(traffic.response({sendRequest:[valid]},request,body),true);
 const cases=[['singleMessage',{}],['singleMessage',{sendRequest:[valid,valid]}],['messageObject',{sendRequest:[null]}],['requestMatches',{sendRequest:[{...valid,requestHeader:'secret-value'}]}],['headerPresent',{sendRequest:[{...valid,responseHeader:null}]}],['headerBounded',{sendRequest:[{...valid,responseHeader:'x'.repeat(16385)}]}],['status200',{sendRequest:[{...valid,responseHeader:valid.responseHeader.replace('200','403')}]}],['squidVia',{sendRequest:[{...valid,responseHeader:'HTTP/1.1 200 OK\r\n\r\n'}]}],['noRedirect',{sendRequest:[{...valid,responseHeader:valid.responseHeader+'Location: http://external.test/\r\n'}]}],['bodyMatches',{sendRequest:[{...valid,responseBody:'secret-value'}]}]];
 for(const [predicate,value] of cases)assert.throws(()=>traffic.response(value,request,body),e=>e.code==='COMMISSIONING_RESPONSE_BLOCKED'&&e.responseDiagnostic.failedPredicates.includes(predicate)&&!JSON.stringify(e.responseDiagnostic).includes('secret-value'));
});
test('response failure persists private bounded evidence before caller cleanup',async t=>{
 const fs=require('fs/promises'),path=require('path'),d=setup(t,'redirect');let error;
 await assert.rejects(traffic.collect({...d,scannerId:'a'.repeat(64),gatewayId:'gateway',clientIp:'172.30.1.3',apiKey:'private-key',proxy:'http://172.30.1.4:3128',verify:async()=>{}}),e=>{error=e;return e.code==='COMMISSIONING_RESPONSE_BLOCKED';});
 assert.equal(d.requests,1);assert(error.responseEvidenceFile);
 try{const text=await fs.readFile(error.responseEvidenceFile,'utf8'),r=JSON.parse(text);assert.equal(r.executionId,100);assert(r.diagnostic.failedPredicates.includes('noRedirect'));assert(!text.includes('private-key'));assert.equal((await fs.stat(path.dirname(error.responseEvidenceFile))).mode&0o777,0o700);assert.equal((await fs.stat(error.responseEvidenceFile)).mode&0o777,0o600);}finally{await fs.rm(path.dirname(error.responseEvidenceFile),{recursive:true});}
});
test('response persistence failure preserves original rejection and stops subsequent requests',async t=>{
 const d=setup(t,'redirect');t.mock.method(require('../services/commissioningResponseEvidence'),'save',async()=>{throw Error('disk secret');});
 await assert.rejects(traffic.collect({...d,scannerId:'scanner',gatewayId:'gateway',clientIp:'172.30.1.3',apiKey:'private-key',proxy:'http://172.30.1.4:3128',verify:async()=>{}}),e=>e.code==='COMMISSIONING_RESPONSE_BLOCKED'&&e.responseEvidenceError==='COMMISSIONING_RESPONSE_EVIDENCE_WRITE_FAILED');assert.equal(d.requests,1);
});
test('private response evidence redacts logs and represents unavailable logs honestly',async()=>{
 const fs=require('fs/promises'),path=require('path'),save=require('../services/commissioningResponseEvidence').save;
 for(const access of [null,{exitCode:0,stderr:'',stdout:'Authorization: Bearer private-header\nTOKEN=private-token\n'+('x'.repeat(40000))}]){
  const file=await save({authorization:{projectId:11,executionId:25,userId:3},index:0,diagnostic:{failedPredicates:['requestMatches']},access,secrets:['private-header']});
  try{const text=await fs.readFile(file,'utf8'),r=JSON.parse(text);assert(!text.includes('private-header'));assert(!text.includes('private-token'));assert(Buffer.byteLength(text)<=32768);assert.equal(r.accessLog.status,access?'COLLECTED':'UNAVAILABLE');}finally{await fs.rm(path.dirname(file),{recursive:true});}
 }
});

test('request differences identify the genuinely observed Host header casing',()=>{
 const expected='GET http://fixture.test:18080/test/sqli?id=1&cs_commission=abc HTTP/1.1\r\nHost: fixture.test:18080\r\nConnection: close\r\n\r\n';
 const actual=expected.replace('Host:','host:');const d=traffic.requestDifference(actual,expected);assert(d.headerNameCaseOnly);assert(Object.values(d.matches).every(Boolean));assert(d.firstDifferingByteOffsets.length);assert(!JSON.stringify(d).includes('fixture.test'));
 assert.equal(traffic.response({sendRequest:[{requestHeader:actual,responseHeader:'HTTP/1.1 200 OK\r\nVia: 1.1 squid\r\n\r\n',responseBody:'body'}]},expected,'body'),true);
});
test('request difference diagnostics isolate destination, query and sensitive-header changes without exposing values',()=>{
 const expected='GET http://fixture.test:18080/test/sqli?id=1 HTTP/1.1\r\nHost: fixture.test:18080\r\nConnection: close\r\n\r\n';
 for(const [actual,field] of [[expected.replace('http:','https:'),null],[expected.replace('fixture.test','other.test'),'host'],[expected.replace('/test/sqli','/test/xss'),'pathQuery'],[expected.replace('id=1','id=2'),'pathQuery'],[expected.replace('Connection: close','Connection: keep-alive'),'connectionHeader']]){const d=traffic.requestDifference(actual,expected);if(field)assert.equal(d.matches[field],false);else assert.equal(d.actualStructured,false);}
 for(const actual of [expected.replace('Connection: close','Host: duplicate.test'),expected.replace('Connection: close','Authorization: Bearer private-secret'),expected+'payload',expected.replace(/\r\n/g,'\n'),expected.replace('Connection: close','Connection: close\r\nX-Injected: value')]){const d=traffic.requestDifference(actual,expected);assert.equal(d.actualStructured,false);assert(!JSON.stringify(d).includes('private-secret'));}
});

test('only the captured Host name normalization is accepted; all other bytes remain strict',()=>{
 const expected='GET http://fixture.test:18080/test/sqli?id=1&cs_commission=abc HTTP/1.1\r\nHost: fixture.test:18080\r\nConnection: close\r\n\r\n';
 const observed=expected.replace('Host:','host:');
 const message={requestHeader:observed,requestBody:'',responseHeader:'HTTP/1.1 200 OK\r\nVia: 1.1 squid\r\n\r\n',responseBody:'body'};
 assert.equal(traffic.response({sendRequest:[message]},expected,'body'),true);
 for(const actual of [observed.replace('GET ','POST '),observed.replace('http:','https:'),observed.replace('fixture.test','escape.test'),observed.replace(':18080',':18081'),observed.replace('/test/sqli','/test/xss'),observed.replace('id=1','id=2'),observed.replace('host: fixture.test','host: other.test'),observed.replace('Connection: close','Connection: keep-alive'),observed.replace('Connection:','connection:'),observed.replace('host:','HOST:'),observed.replace('Connection: close','host: duplicate.test'),observed.replace('Connection: close','Connection: close\r\nAuthorization: injected'),observed+'payload',observed.replace(/\r\n/g,'\n')]){
  assert.throws(()=>traffic.response({sendRequest:[{...message,requestHeader:actual}]},expected,'body'),e=>e.code==='COMMISSIONING_RESPONSE_BLOCKED'&&e.responseDiagnostic.failedPredicates.includes('requestMatches'));
 }
 for(const requestBody of ['payload',null,{}])assert.throws(()=>traffic.response({sendRequest:[{...message,requestBody}]},expected,'body'),e=>e.responseDiagnostic.failedPredicates.includes('requestBodyEmpty'));
});


test('Squid query-stripped runtime shape remains blocked; complete nonce records are required',()=>{
 const nonce='a'.repeat(32),clientIp='172.30.180.243',hostname='cr-p11-final-1016-c1.test';
 const observed=`1792164345.306 ${clientIp} GET http://${hostname}:18080/test/sqli? 200 TCP_MISS/HIER_DIRECT\n1792164346.442 ${clientIp} GET http://${hostname}:18080/test/xss? 200 TCP_MISS/HIER_DIRECT\n`;
 assert.throws(()=>traffic.correlate(observed,{nonce,clientIp,hostname}),{code:'COMMISSIONING_PROXY_CORRELATION_BLOCKED'});
 const complete=observed.replace('sqli?','sqli?id=1&cs_commission='+nonce+'-0').replace('xss?','xss?q=hello&cs_commission='+nonce+'-1');
 assert.equal(traffic.correlate(complete,{nonce,clientIp,hostname}).length,2);
 for(const text of [complete.replace(nonce,'b'.repeat(32)),complete.replace(clientIp,'172.30.180.244'),complete.replace(' 200 ',' 403 '),complete+complete.split('\n')[0]+'\n'])assert.throws(()=>traffic.correlate(text,{nonce,clientIp,hostname}),{code:'COMMISSIONING_PROXY_CORRELATION_BLOCKED'});
});

test('failed Automation command preserves native partial output before external cleanup',async t=>{
 const d=setup(t),scannerId='a'.repeat(64),calls=[];let verification=0,error;
 const adapter={async run(args){calls.push(args);if(args[1]==='-d')return {exitCode:0,stdout:'',stderr:''};if(args.at(-1)==='/tmp/cloudsentinel-active-access.log')return {exitCode:0,stderr:'',stdout:''};if(args.at(-1).endsWith('.exit'))throw Object.assign(Error('native exec failed'),{code:'DOCKER_COMMAND_FAILED'});if(args.at(-1).endsWith('.log'))return {exitCode:0,stderr:'',stdout:'Unknown Automation output\napi.key=private-key\n'};throw Error('unexpected command');}};
 await assert.rejects(traffic.executePlan({adapter,scannerId,gatewayId:'gateway',index:0,args:['-cmd','-config','api.key=private-key','-autorun','/zap/wrk/plan-0.yaml'],authorization:d.authorization,verify:async()=>{verification++;}}),e=>{error=e;return e.code==='DOCKER_COMMAND_FAILED'&&!!e.automationEvidenceFile;});
 const fs=require('fs/promises'),path=require('path');try{const text=await fs.readFile(error.automationEvidenceFile,'utf8'),r=JSON.parse(text);assert(!text.includes('private-key'));assert.equal(r.stdout.unrecognized[0].text,'Unknown Automation output');assert.equal(r.source,'AUTOMATION_LOG_READ');assert.equal(r.exitCode,null);assert.equal(r.captureExitCode,0);assert(verification>=3);assert(!calls.some(a=>['stop','rm'].includes(a[0])));}finally{await fs.rm(path.dirname(error.automationEvidenceFile),{recursive:true});}
});
test('failed ownership verification never reads extra Automation logs',async t=>{
 const d=setup(t),calls=[];
 await assert.rejects(traffic.executePlan({adapter:{async run(a){calls.push(a);}},scannerId:'a'.repeat(64),gatewayId:'gateway',index:0,args:['-cmd','-autorun','/zap/wrk/plan-0.yaml'],authorization:d.authorization,verify:async()=>{throw Object.assign(Error('ownership mismatch'),{code:'ACTIVE_SCANNER_IDENTITY_BLOCKED'});}}),e=>e.code==='ACTIVE_SCANNER_IDENTITY_BLOCKED'&&!e.automationEvidenceFile);
 assert.equal(calls.length,0);
});

test('Automation wrapper rejects a duplicate zap.sh executable before any command',async()=>{
 let calls=0;
 await assert.rejects(traffic.executePlan({adapter:{run(){calls++;}},scannerId:'a'.repeat(64),gatewayId:'b'.repeat(64),index:0,args:['zap.sh','-cmd','-autorun','/zap/wrk/plan-0.yaml'],authorization:{},verify:async()=>{}}),{code:'COMMISSIONING_PLAN_BLOCKED'});
 assert.equal(calls,0);
});
