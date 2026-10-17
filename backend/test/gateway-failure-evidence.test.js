'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs/promises'),os=require('os'),path=require('path');
const evidence=require('../services/gatewayFailureEvidence'),{mockDocker}=require('./helpers/runtimeDocker');
async function root(t){const r=await fs.mkdtemp(path.join(os.tmpdir(),'cs-gateway-evidence-test-'));t.after(()=>fs.rm(r,{recursive:true,force:true}));return r;}
function sample({stopped=false,foreign=false,missingLogs=false}={}){
 const calls=[],id='3'.repeat(64),networkId='1'.repeat(64),owner='cloudsentinel-s1';
 const adapter={async inspect(){calls.push('inspect');return {normalized:{objectId:id,labels:{'cloudsentinel.owner':foreign?'foreign':owner,'cloudsentinel.scan':'s1','cloudsentinel.role':'gateway'},state:{Running:!stopped,ExitCode:stopped?1:0,OOMKilled:stopped},networks:{scanner:{NetworkID:networkId,IPAddress:stopped?'':'172.30.25.9'}}}};},async run(args){calls.push(args);if(missingLogs)throw Object.assign(Error('secret log unavailable'),{code:'MISSING_RESOURCE'});return {exitCode:0,stdout:'startup\n',stderr:'Read-only file system\n'};}};
 return {adapter,calls,resources:{gatewayId:id,owner,gatewayBinding:{networkId,networkName:'scanner',ip:'172.30.25.3'},owned:{networks:[{id:networkId,name:'scanner'}]}},projectId:11,executionId:24,scanId:'s1',error:{code:'INVALID_PROBE',gatewayDiagnostic:{gatewayRunning:!stopped,expectedProxyIp:'172.30.25.3',inspectedGatewayIp:'172.30.25.9',proxyMatches:false}}};
}
test('mismatch evidence retains private execution linkage, observed state and distinct expected/observed IPs',async t=>{
 const baseDir=await root(t),input=sample(),file=await evidence.save(input,{baseDir}),r=JSON.parse(await fs.readFile(file));
 assert.equal(r.executionId,24);assert.equal(r.projectId,11);assert.equal(r.expected.ip,'172.30.25.3');assert.equal(r.inspection.networks[0].ip,'172.30.25.9');assert.equal(r.inspection.ownershipMatches,true);assert.equal(r.logs.status,'COLLECTED');assert.equal(r.inspection.exitCode,0);assert.equal(r.inspection.oomKilled,false);
 assert.equal((await fs.stat(path.dirname(file))).mode&0o777,0o700);assert.equal((await fs.stat(file)).mode&0o777,0o600);assert.deepEqual(input.calls[1],['logs','--tail','200','3'.repeat(64)]);
});
test('stopped gateway retains exit and OOM state without inventing a missing IP',async t=>{const file=await evidence.save(sample({stopped:true}),{baseDir:await root(t)}),r=JSON.parse(await fs.readFile(file));assert.equal(r.inspection.running,false);assert.equal(r.inspection.exitCode,1);assert.equal(r.inspection.oomKilled,true);assert.equal(r.inspection.networks[0].ip,null);});
test('missing logs or inspection are recorded as unavailable, never successful observations',async t=>{
 const baseDir=await root(t);for(const kind of ['logs','inspect']){const input=sample({missingLogs:true});if(kind==='inspect')input.adapter.inspect=async()=>{throw Object.assign(Error('private'),{code:'MISSING_RESOURCE'});};const r=JSON.parse(await fs.readFile(await evidence.save(input,{baseDir})));assert.equal(r.logs.status,kind==='logs'?'UNAVAILABLE':'INSPECTION_UNAVAILABLE');assert(!JSON.stringify(r).includes('private'));}
});
test('foreign ownership prevents log collection while retaining safe identity mismatch',async t=>{const input=sample({foreign:true});const r=JSON.parse(await fs.readFile(await evidence.save(input,{baseDir:await root(t)})));assert.equal(r.inspection.ownershipMatches,false);assert.equal(r.logs.status,'OWNERSHIP_UNVERIFIED');assert(!input.calls.some(c=>Array.isArray(c)&&c[0]==='logs'));});
test('credentials, environment secrets, sensitive headers and JSON secrets are redacted before byte truncation',async t=>{
 const input=sample(),secrets=['private-bare-value'];input.adapter.run=async()=>({exitCode:0,stdout:'Authorization: Bearer header-value\nProxy-Authorization: Basic base64-value\nSet-Cookie: cookie-value\nX-Api-Key: header-secret\nCUSTOM_ENV=environment-value\n{"password":"json-value"}\nhttp://user:uri-password@fixture.test/\nprivate-bare-value\n'+'a'.repeat(20000),stderr:'token: private-token\n'});
 const file=await evidence.save(input,{baseDir:await root(t),secrets}),raw=await fs.readFile(file,'utf8'),r=JSON.parse(raw);
 for(const secret of ['header-value','base64-value','cookie-value','header-secret','environment-value','json-value','uri-password','private-bare-value','private-token'])assert(!raw.includes(secret));
 assert(r.logs.stdout.truncated);assert(Buffer.byteLength(r.logs.stdout.text)<=evidence.MAX_LOG);assert(Buffer.byteLength(raw)<=evidence.MAX_FILE);
});
test('private persistence errors have a stable sanitized failure code',async t=>{const input=sample(),baseDir=await root(t);await assert.rejects(evidence.save(input,{baseDir,fsImpl:{...fs,open:async()=>{throw Error('disk failure secret-value');}}}),e=>e.code==='GATEWAY_EVIDENCE_WRITE_FAILED'&&!e.message.includes('secret-value'));});
function lifecycle(t,baseDir,{persistenceFailure=false}={}){
 const d=mockDocker();let cleaned=false;
 const original=evidence.save;t.mock.method(evidence,'save',async input=>{assert.equal(cleaned,false);if(persistenceFailure)throw Object.assign(Error('disk full'),{code:'GATEWAY_EVIDENCE_WRITE_FAILED'});return original(input,{baseDir});});
 const observation={bindAcceptanceClient(){},clearAcceptanceClient(){},async collect(){throw Object.assign(Error('original gateway mismatch'),{code:'INVALID_PROBE',gatewayDiagnostic:{expectedProxyIp:'172.30.25.3',inspectedGatewayIp:'172.30.25.9',proxyMatches:false}});}};
 const Gateway=require('../services/dastGateway').SecureGatewayLifecycle;
 const l=new Gateway({adapter:d.adapter,observation,networks:{async create(){return {networks:d.refs};},async cleanup(){cleaned=true;return {residual:[]};}},fixture:{async provision(){return {id:'f'.repeat(64),ip:'172.30.26.2'};},async cleanup(){return {cleaned:true};}},policyService:{async stagePolicy(){return {filePath:'/tmp/mock-policy',containerPath:'/etc/squid/cloudsentinel/squid.conf',policyDigest:'sha256'+d.state.digest};},async verifyStagedPolicy(){},async cleanupPolicy(){}}});
 return {l,d,cleaned:()=>cleaned};
}
test('evidence is saved before lifecycle removal and survives successful cleanup',async t=>{
 const baseDir=await root(t),h=lifecycle(t,baseDir);let failure;
 await assert.rejects(h.l.provision({projectId:'11',executionId:'24',scanId:'s1',target:{hostname:'fixture.test',port:8080}}),e=>{failure=e;return e.code==='INVALID_PROBE';});
 assert(h.cleaned());assert.equal(h.l.resources.size,0);assert.equal(h.l.states.get('s1'),'CLEANED');assert(failure.gatewayEvidenceFile);assert((await fs.stat(failure.gatewayEvidenceFile)).isFile());
 const logIndex=h.d.calls.findIndex(a=>a[0]==='logs'),removeIndex=h.d.calls.findIndex(a=>a[0]==='rm');assert(logIndex>=0&&removeIndex>logIndex);
});
test('persistence failure never skips cleanup or overwrites original verification failure',async t=>{
 const h=lifecycle(t,await root(t),{persistenceFailure:true});await assert.rejects(h.l.provision({projectId:'11',executionId:'24',scanId:'s1',target:{hostname:'fixture.test',port:8080}}),e=>e.code==='INVALID_PROBE'&&e.message==='original gateway mismatch'&&e.gatewayEvidenceError==='GATEWAY_EVIDENCE_WRITE_FAILED');assert(h.cleaned());assert.equal(h.l.resources.size,0);
});
test('Docker log operation permits only bounded immutable-ID inspection',()=>{const {operation}=require('../services/dockerAdapter');assert.deepEqual(operation(['logs','--tail','200','3'.repeat(64)]),['logs','--tail','200','3'.repeat(64)]);for(const args of [['logs','gateway'],['logs','--follow','3'.repeat(64)],['logs','--tail','all','3'.repeat(64)],['logs','--tail','200','gateway'],['logs','--tail','200','3'.repeat(64),'--follow']])assert.throws(()=>operation(args));});
