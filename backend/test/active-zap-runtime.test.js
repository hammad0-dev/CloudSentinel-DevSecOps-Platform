'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs/promises'),path=require('path');
const {ActiveZapRuntime,capabilities,proxyPolicy,runArguments}=require('../services/activeZapRuntime');
const {mockDocker}=require('./helpers/runtimeDocker');
function catalog(){const entry=(name,id)=>({reference:`${name}@sha256:${id.repeat(64)}`,imageId:'sha256:'+id.repeat(64),architecture:'amd64',os:'linux'});const zap=entry('zap/test','a'),fixture={...entry('fixture/test','b'),fixtureKind:'cloudsentinel-vulnerable-v1'};zap.capabilities={initialization:require('./helpers/zapInitializationEvidence')(zap.imageId),verified:true,runtimeContract:{zapApplicationProxyVerified:true,rateEnforcementVerified:true,redirectEnforcementVerified:true,apiBinding:'LOOPBACK_ONLY',apiAuthentication:'REQUIRED',maxRequestsPerSecond:2,maxConcurrency:1,spiderRateLimited:true,exactPathScope:true,jobCompletionVerified:true,timeoutVerified:true,cancellationVerified:true,exportFormat:'traditional-json',evidenceSha256:'e'.repeat(64)},imageId:zap.imageId,activeRuleIds:require('../config/zap-active-policy-v1.json').approvedPluginIds,commands:['automation','spider','activeScan','report','proxy','rateLimit','sha256sum','python3']};return {zap,fixture};}
async function setup(t,scenario='ok'){
  const old=process.env.NODE_ENV,flag=process.env.DAST_ACTIVE_ENABLED;process.env.NODE_ENV='test';process.env.DAST_ACTIVE_ENABLED='true';t.after(()=>{if(old===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=old;if(flag===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=flag;});
  const d=mockDocker(),c=catalog(),fixtureId='f'.repeat(64),scannerId='5'.repeat(64),a={hostname:'fixture.test',ip:'172.30.26.2',port:18080,fixtureContainerId:fixtureId,scannerNetworkId:d.ids.scanner};let directory,removed=false,scannerCreated=false;
  const resources={fixtureResource:{id:fixtureId,networkId:d.ids.fixture},acceptanceClientId:d.ids.client,runtimeObservation:{verification:'RUNTIME_OBSERVED',complete:true,independent:true,scannerContainerId:d.ids.client,scannerNetworkId:d.ids.scanner,ipv6:false,directTcpBypass:false,routes:{ipv4:[],ipv6:[],addresses:[]}},gatewayId:d.ids.gateway,owned:{networks:d.refs},staged:{filePath:'/tmp/owned-squid-unit',containerPath:'/etc/squid/cloudsentinel/squid.conf'}};
  const lifecycle={resources:new Map([['s1',resources]]),async cleanup(){d.calls.push(['lifecycle-cleanup']);return {state:'CLEANED',residual:[]};}};
  const inspect=d.adapter.inspect.bind(d.adapter),run=d.adapter.run.bind(d.adapter);
  d.adapter.inspect=async(args,kind)=>{
    if(kind==='container'&&args[0]==='cs-zap-s1'&&scannerCreated)args=[scannerId];
    if(kind==='container'&&[fixtureId,scannerId].includes(args[0])){
      const fixture=args[0]===fixtureId;const n={imageId:fixture?c.fixture.imageId:c.zap.imageId,objectId:args[0],imageDigest:fixture?c.fixture.reference:c.zap.reference,state:{Running:true},labels:{'cloudsentinel.owner':scenario==='owner'?'foreign':'cloudsentinel-s1','cloudsentinel.role':fixture?'fixture':'active-zap'},networks:fixture?{'cs-fixture':{NetworkID:d.ids.fixture,IPAddress:scenario==='dns'?'172.30.26.9':a.ip}}:d.state.clientNetworks,security:{readOnly:true,privileged:false,capAdd:[],capDrop:['ALL'],securityOpt:['no-new-privileges:true']},mounts:fixture?[]:[{Source:directory,Destination:'/zap/wrk',RW:false}]};
      if(scenario==='image'&&fixture)n.imageDigest=c.zap.reference;
      return {normalized:n};
    }return inspect(args,kind);
  };
  d.adapter.run=async args=>{
    if(args[0]==='image'){const image=[c.zap,c.fixture].find(i=>i.reference===args[2]);return {exitCode:0,stderr:'',stdout:JSON.stringify([{Id:image.imageId,Architecture:image.architecture,Os:image.os,RepoDigests:[image.reference]}])};}
    if(args[0]==='run'){scannerCreated=true;d.calls.push(args);directory=args[args.indexOf('--mount')+1].split('src=')[1].split(',')[0];if(scenario==='uncertain-scanner')throw Object.assign(Error('lost response'),{code:'DOCKER_COMMAND_FAILED'});return {stdout:scannerId,exitCode:0,stderr:''};}
    if(args[0]==='inspect'&&args.at(-1)===d.ids.gateway){const out=await run(args),raw=JSON.parse(out.stdout);raw.Config.User=`${process.getuid()}:${process.getgid()}`;Object.assign(raw.HostConfig,{Memory:268435456,NanoCpus:1000000000,PidsLimit:64});raw.Mounts=[{Source:'/tmp/owned-squid-unit',Destination:'/etc/squid/cloudsentinel/squid.conf',RW:false}];return {...out,stdout:JSON.stringify(raw)};}
    if(args[0]==='inspect'&&args.at(-1)===scannerId)return {exitCode:0,stderr:'',stdout:JSON.stringify({Config:{User:'1000:1000'},HostConfig:{NetworkMode:d.ids.scanner,ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],SecurityOpt:['no-new-privileges:true'],Memory:1536*1048576,NanoCpus:1000000000,PidsLimit:128,Sysctls:{'net.ipv6.conf.all.disable_ipv6':'1','net.ipv6.conf.default.disable_ipv6':'1'},Tmpfs:{'/tmp':'rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=1777','/home/zap/.ZAP':require('../services/zapInitialization').homeTmpfs().split(':')[1],[require('../config/zap-writable-paths.json').profilePath]:require('../services/zapInitialization').profileTmpfs().split(':')[1]}},Mounts:[{Source:directory,Destination:'/zap/wrk',RW:false}],NetworkSettings:{Ports:{}}})};
    if(args[0]==='inspect'&&args.at(-1)===fixtureId)return {stdout:JSON.stringify({HostConfig:{PortBindings:scenario==='published'?{'18080/tcp':[{}]}:{}},NetworkSettings:{Ports:{}}}),stderr:'',exitCode:0};
    if(args[0]==='exec'&&args[1]===d.ids.gateway&&args[2]==='cat')return {stdout:scenario==='policy'?'allow all':proxyPolicy(a),stderr:'',exitCode:0};
    if(args[0]==='exec'&&args[1]===scannerId){
      d.calls.push(args);
      if(args[2]==='python3')return {exitCode:scenario==='seed-failure'||(scenario==='jvm-failure'&&args.includes('.ZAP_JVM.properties'))?1:0,stdout:'',stderr:''};
      if(args[2]==='ip')return {stdout:args.includes('address')?d.state.addresses:args.includes('inet6')?'':d.state.route,stderr:'',exitCode:0};
      if(args[2]==='sha256sum'){
        if(args[3].startsWith('/home/zap/.mozilla/'))return {exitCode:0,stderr:'',stdout:(scenario==='seed-mismatch'?'wrong':require('../config/zap-writable-paths.json').profileSeed.sha256)+'  '+args[3]+'\n'};
        if(args[3].endsWith('/.ZAP_JVM.properties'))return {exitCode:0,stderr:'',stdout:require('../services/zapInitialization').jvmBootstrapArguments().at(-1)+'  '+args[3]+'\n'};
        const file=path.join(directory,path.basename(args[3]));return {stdout:require('crypto').createHash('sha256').update(await fs.readFile(file)).digest('hex')+'  '+args[3]+'\n',stderr:'',exitCode:0};
      }
      if(args[2]==='zap.sh')return {exitCode:scenario==='interrupted'?1:0,stdout:scenario==='storage'?'java.io.IOException: No space left on device':scenario==='policy-init'?'SAXParseException: Premature end of file':scenario==='automation-unknown'?'Unexpected automation console line':scenario==='automation-malformed'?'100 [ZAP-daemon] INFO org.example - broken\u0000':scenario==='automation-valid'?'Job report started\nJob report finished, time taken: 00:00:01\nAutomation plan succeeded!':'100 [ZAP-daemon] INFO org.zaproxy.addon.automation.ExtensionAutomation - jobs finished',stderr:''};
      if(args[2]==='cat')return {exitCode:0,stderr:'',stdout:scenario==='report'?'{}':JSON.stringify({site:[]})};
    }
    if(['stop','rm'].includes(args[0])&&args[1]===scannerId){d.calls.push(args);if(scenario==='cleanup')throw Object.assign(Error('busy'),{code:'BUSY'});if(args[0]==='rm')removed=true;return {stdout:'',stderr:'',exitCode:0};}
    return run(args);
  };
  const binding=require('../services/activeScannerBinding');
  t.mock.method(binding,'bind',async()=>{resources.runtimeObservation={...resources.runtimeObservation,namespaceScope:'ZAP_SHARED_NETWORK_NAMESPACE',namespaceEvidence:{zapContainerId:scannerId,helperId:d.ids.client,equivalent:true,source:'LIVE_PROC_SELF_NS_NET'}};return {token:{},helper:{id:d.ids.client}};});
  t.mock.method(binding,'verify',async()=>{if(scenario==='namespace-binding')throw Object.assign(Error('namespace'),{code:'ACTIVE_NAMESPACE_BLOCKED'});return resources.runtimeObservation.namespaceEvidence;});
  const runtime=new ActiveZapRuntime({adapter:d.adapter,lifecycle,scanId:'s1',catalog:c,offline:true});
  return {...d,runtime,a,c,lifecycle,removed:()=>removed,directory:()=>directory};
}
test('artifact capabilities and exact route policy block unsupported images/rules/scope',()=>{
  assert.doesNotThrow(()=>capabilities(catalog()));
  for(const mutate of [c=>{c.fixture=null;},c=>{c.zap.architecture='arm64';},c=>{c.zap.capabilities.activeRuleIds=['1'];},c=>{c.zap.capabilities.commands=[];}]){const c=catalog();mutate(c);assert.throws(()=>capabilities(c));}
  const policy=proxyPolicy({hostname:'fixture.test',ip:'172.30.26.2',port:18080});assert.ok(policy.includes('http_access deny connect'));assert.ok(policy.includes('^/test/(sqli|xss)'));assert.ok(policy.includes('http_access deny all'));
  assert.throws(()=>proxyPolicy({hostname:'169.254.169.254',ip:'169.254.169.254',port:80}));
});
test('pinned ZAP capability contract has no ip or nc dependency',()=>{
  const c=catalog();assert.doesNotThrow(()=>capabilities(c));
  for(const command of ['ip','nc']){const bad=catalog();bad.zap.capabilities.commands.push(command);assert.throws(()=>capabilities(bad),{code:'ACTIVE_POLICY_CAPABILITIES_BLOCKED'});}
});
test('scanner arguments enforce read-only scope and restrictions without Docker',()=>{
  const args=runArguments({scanId:'s1',networkId:'1'.repeat(64),image:catalog().zap.reference,directory:'/tmp/owned',proxy:'http://172.30.25.3:3128',hostname:'fixture.test',ip:'172.30.26.2'});
  for(const flag of ['--pull=never','--read-only','--cap-drop','--security-opt','--pids-limit','--memory','--cpus','--hostname','--tmpfs'])assert.ok(args.includes(flag));assert.ok(!args.includes('--publish'));assert.ok(args.includes('type=bind,src=/tmp/owned,dst=/zap/wrk,readonly'));assert.ok(args.includes('/home/zap/.ZAP:rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700'));assert.ok(args.includes('cs-zap-s1:127.0.0.1'));assert.equal(args[args.indexOf('--memory')+1],'1536m');
});
test('adapter controls only verified scanner, rechecks namespace and cleans live lifecycle ownership',async t=>{
  const d=await setup(t);const session=await d.runtime.provision({authorization:d.a});
  try{await d.runtime.verify(session,d.a);const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));const result=await d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1});assert.equal(result.completed,true);assert.equal(d.calls.filter(a=>a[2]==='zap.sh').length,2);assert.ok(d.calls.filter(a=>a[2]==='zap.sh').every(a=>a.includes('connection.proxyChain.hostName=172.30.25.3')&&a.includes('oast.callback.localaddr=127.0.0.1')&&!a.some(arg=>arg.startsWith('-Djava.'))&&a[a.indexOf('-dir')+1]==='/home/zap/.ZAP'));assert.ok(d.calls.findIndex(a=>a.includes('.ZAP_JVM.properties'))<d.calls.findIndex(a=>a[2]==='zap.sh'));}finally{assert.equal((await d.runtime.cleanup(session)).cleaned,true);}assert.equal(d.removed(),true);await assert.rejects(fs.stat(d.directory()),{code:'ENOENT'});
});
test('wrong image, DNS/address change, ownership, ports or path policy block scanner creation',async t=>{
  for(const scenario of ['image','dns','owner','published','policy']){
    const d=await setup(t,scenario);try{await assert.rejects(d.runtime.provision({authorization:d.a}));assert.ok(!d.calls.some(a=>a[0]==='run'));}finally{assert.equal((await d.runtime.cleanup()).cleaned,true);}
  }
});
test('interrupted scans and incomplete reports fail with cleanup',async t=>{
  for(const scenario of ['interrupted','report','storage','policy-init']){const d=await setup(t,scenario),session=await d.runtime.provision({authorization:d.a});const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));try{await assert.rejects(d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1}));}finally{assert.equal((await d.runtime.cleanup(session)).cleaned,true);}}
});
test('incomplete initialization blocks Active provisioning before any Docker command',async t=>{
  const d=await setup(t);d.c.zap.capabilities.initialization.complete=false;
  await assert.rejects(d.runtime.provision({authorization:d.a}),{code:'ZAP_INITIALIZATION_INCOMPLETE'});
  assert.equal(d.calls.length,0);assert.equal((await d.runtime.cleanup()).cleaned,true);
});
test('failed or changed profile seed blocks ZAP execution and preserves cleanup',async t=>{
  for(const scenario of ['seed-failure','seed-mismatch','jvm-failure']){
    const d=await setup(t,scenario),session=await d.runtime.provision({authorization:d.a});
    const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));
    try{await assert.rejects(d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1}),{code:scenario==='jvm-failure'?'ZAP_PREFERENCES_NOT_READY':'ZAP_PROFILE_NOT_READY'});assert.ok(!d.calls.some(a=>a[2]==='zap.sh'));}
    finally{assert.equal((await d.runtime.cleanup(session)).cleaned,true);}
  }
});
test('foreign scanner ownership preserves container and mounted artifacts during cleanup failure',async t=>{
  const d=await setup(t,'cleanup'),session=await d.runtime.provision({authorization:d.a});
  const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));
  await d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1});
  const result=await d.runtime.cleanup(session);assert.equal(result.cleaned,false);assert.ok(result.residual.some(r=>r.type==='active-zap'));assert.ok(!d.calls.some(a=>a[0]==='lifecycle-cleanup'));assert.ok((await fs.stat(d.directory())).isDirectory());
  // Test teardown only: these are local mock files, never a container mount.
  await fs.rm(d.directory(),{recursive:true,force:true});
});
test('changed plan and cancellation block scanning before command execution',async t=>{
  const d=await setup(t),session=await d.runtime.provision({authorization:d.a});
  try {await assert.rejects(d.runtime.scan(session,{plans:['bad','bad'],maxRequestsPerSecond:2,maxConcurrency:1}),{code:'ACTIVE_POLICY_CAPABILITIES_BLOCKED'});assert.ok(!d.calls.some(a=>a[2]==='zap.sh'));}
  finally {await d.runtime.cleanup(session);}
});
test('a lost scanner-create response recovers only the owned immutable image before cleanup',async t=>{
 const d=await setup(t,'uncertain-scanner'),session=await d.runtime.provision({authorization:d.a});
 const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));
 await assert.rejects(d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1}),{code:'DOCKER_COMMAND_FAILED'});
 assert.equal((await d.runtime.cleanup(session)).cleaned,true);assert.equal(d.removed(),true);
});
test('fresh production namespace verification failure stops the scanner before any ZAP job',async t=>{
 const d=await setup(t,'namespace-binding'),session=await d.runtime.provision({authorization:d.a});
 const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));
 await assert.rejects(d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1}),{code:'ACTIVE_NAMESPACE_BLOCKED'});
 assert.ok(!d.calls.some(a=>a[0]==='exec'&&a[2]==='zap.sh'));assert.equal((await d.runtime.cleanup(session)).cleaned,true);
});
test('configured rate or helper-only containment cannot replace application, enforcement or redirect proof',()=>{
 for(const field of ['zapApplicationProxyVerified','rateEnforcementVerified','redirectEnforcementVerified']){const c=catalog();c.zap.capabilities.runtimeContract[field]=false;assert.throws(()=>capabilities(c),{code:'ACTIVE_POLICY_CAPABILITIES_BLOCKED'});}
});
test('pre-consumption runtime preflight inspects immutable artifacts and target without creating a scanner',async t=>{
 const d=await setup(t),a={...d.a,projectId:42,executionId:100,userId:7,fixtureKind:'cloudsentinel-vulnerable-v1',scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:d.c.zap.imageId,expiresAt:Date.now()+60000};
 assert.deepEqual(await d.runtime.preflight(a),{verified:true,scannerNamespace:'REQUIRES_FRESH_SCANNER_BINDING'});
 assert.ok(!d.calls.some(a=>['run','stop','rm'].includes(a[0])));
});


test('Automation console success still requires command completion and a parsed report',async t=>{
 const d=await setup(t,'automation-valid'),session=await d.runtime.provision({authorization:d.a});
 const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));
 try{assert.equal((await d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1})).completed,true);}finally{assert.equal((await d.runtime.cleanup(session)).cleaned,true);}
});
for(const scenario of ['automation-unknown','automation-malformed','storage','policy-init'])test('private native output survives cleanup after '+scenario,async t=>{
 const d=await setup(t,scenario);Object.assign(d.a,{projectId:11,executionId:26});const session=await d.runtime.provision({authorization:d.a});
 const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));let error;
 await assert.rejects(d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1}),e=>{error=e;return !!e.automationEvidenceFile;});
 assert.equal(d.removed(),false);const file=error.automationEvidenceFile,record=JSON.parse(await fs.readFile(file,'utf8'));
 assert.equal(record.executionId,26);assert.equal(record.reason,error.code);assert.equal(record.stdout.available,true);
 if(scenario==='automation-unknown')assert.equal(record.stdout.unrecognized[0].text,'Unexpected automation console line');
 assert.equal((await d.runtime.cleanup(session)).cleaned,true);assert.equal(d.removed(),true);assert.equal((await fs.stat(path.dirname(file))).mode&511,448);assert.equal((await fs.stat(file)).mode&511,384);
 assert.equal(JSON.parse(await fs.readFile(file,'utf8')).reason,error.code);await fs.rm(path.dirname(file),{recursive:true});
});
test('private evidence persistence failure preserves validation failure and mandatory cleanup',async t=>{
 const d=await setup(t,'automation-unknown');Object.assign(d.a,{projectId:11,executionId:26});const session=await d.runtime.provision({authorization:d.a});
 t.mock.method(require('../services/zapAutomationEvidence'),'save',async()=>{throw Error('disk full');});
 const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));
 await assert.rejects(d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1}),e=>e.code==='ZAP_STARTUP_LOG_UNVERIFIED'&&e.automationEvidenceError==='ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED');
 assert.equal((await d.runtime.cleanup(session)).cleaned,true);assert.equal(d.removed(),true);
});

async function warmSetup(t){
 const d=await setup(t),m=require('../services/module2ActiveDast'),c=require('../services/activeDastCommissioning'),traffic=require('../services/zapCommissioningTraffic');
 const a={...d.a,projectId:11,executionId:100,userId:3,authorizationState:'COMMISSIONING',expiresAt:Date.now()+240000,zapImageDigest:d.c.zap.imageId,fixtureKind:'cloudsentinel-vulnerable-v1',scheme:'http',routes:m.ROUTES,policies:['SQLI','XSS'],gatewayContainerId:d.ids.gateway};
 t.mock.method(c,'validate',()=>true);t.mock.method(c,'activeAllowed',()=>true);t.mock.method(c,'runtimeAllowed',()=>true);
 t.mock.method(m,'isBaselineAuthorization',v=>v===a);t.mock.method(m,'isIssuedAuthorization',()=>true);
 const calls=[];t.mock.method(traffic,'collect',async options=>{calls.push(options.requirePassive?'passive-start':'active-start');await options.verify();return {verified:true};});
 t.mock.method(traffic,'executePlan',async options=>{calls.push(options.index);await options.verify();return {exitCode:0,stdout:'Automation plan succeeded!\n',stderr:''};});
 d.lifecycle.states=new Map([['s1','READY']]);
 const result=await d.runtime.baseline({authorization:a});
 const next={...a,retainedScannerId:'5'.repeat(64)};
 const run=d.adapter.run.bind(d.adapter);d.adapter.run=async args=>args.includes('prepare-reuse')?{exitCode:0,stderr:'',stdout:'{"prepared":true}'}:run(args);
 return {...d,a,next,trafficCalls:calls,result};
}
test('passive scanner/home is retained; exact same execution rebinds freshly and starts one Active plan',async t=>{
 const d=await warmSetup(t);assert.equal(d.removed(),false);assert.ok((await fs.stat(d.directory())).isDirectory());
 assert.equal(d.calls.filter(a=>Array.isArray(a)&&a[0]==='run').length,1);
 const checked=await d.runtime.verifyRetained(d.next);assert.equal(checked.reusableScanner,true);
 const session=await d.runtime.provision({authorization:d.next});const budget=require('../services/commissioningBudget').start(Date.now()+180000,{authorization:d.next});
 try{
  const result=await d.runtime.scan(session,{plans:require('../services/module2ActiveDast').plans(d.next),signal:budget.signal,maxRequestsPerSecond:2,maxConcurrency:1});
  assert.equal(result.completed,true);assert.equal(result.timings.reusedScanner,true);assert.equal(result.timings.source,'MONOTONIC_RUNTIME_CLOCK');
  assert.deepEqual(d.trafficCalls.filter(x=>typeof x==='number'),[0,1]);assert.ok(d.trafficCalls.includes('active-start'));
  assert.equal(d.calls.filter(a=>Array.isArray(a)&&a[0]==='run').length,1);
  await assert.rejects(d.runtime.scan(session,{plans:require('../services/module2ActiveDast').plans(d.next),signal:budget.signal,maxRequestsPerSecond:2,maxConcurrency:1}),{code:'ACTIVE_SESSION_BLOCKED'});
 }finally{budget.close();assert.equal((await d.runtime.cleanup()).cleaned,true);}
 assert.equal(d.removed(),true);await assert.rejects(fs.stat(d.directory()),{code:'ENOENT'});
});
for(const scenario of ['execution','gateway','scanner','expired','stopped','namespace','startup','cancelled'])test('retained scanner rejects '+scenario+' and cleans without creating another scanner',async t=>{
 const d=await warmSetup(t);
 try{
  if(['execution','gateway','scanner','expired'].includes(scenario)){
   const patch={execution:{executionId:101},gateway:{gatewayContainerId:'a'.repeat(64)},scanner:{retainedScannerId:'9'.repeat(64)},expired:{expiresAt:Date.now()-1}}[scenario];
   await assert.rejects(d.runtime.provision({authorization:{...d.next,...patch}}));
  }else if(scenario==='stopped'){
   const inspect=d.adapter.inspect.bind(d.adapter);t.mock.method(d.adapter,'inspect',async(args,kind)=>{const r=await inspect(args,kind);if(args[0]==='5'.repeat(64))r.normalized.state.Running=false;return r;});
   await assert.rejects(d.runtime.verifyRetained(d.next),{code:'ACTIVE_SCANNER_IDENTITY_BLOCKED'});
  }else if(scenario==='namespace'){
   t.mock.method(require('../services/activeScannerBinding'),'verify',async()=>{throw Object.assign(Error('stale namespace'),{code:'ACTIVE_NAMESPACE_BLOCKED'});});
   await assert.rejects(d.runtime.verifyRetained(d.next),{code:'ACTIVE_NAMESPACE_BLOCKED'});
  }else if(scenario==='cancelled'){
   const signal=AbortSignal.abort();await assert.rejects(d.runtime.provision({authorization:d.next,signal}),{code:'ACTIVE_CANCELLED'});
  }else{
   const session=await d.runtime.provision({authorization:d.next});
   t.mock.method(require('../services/zapCommissioningTraffic'),'collect',async()=>{throw Object.assign(Error('startup'),{code:'COMMISSIONING_INITIALIZATION_BLOCKED'});});
   await assert.rejects(d.runtime.scan(session,{plans:require('../services/module2ActiveDast').plans(d.next),maxRequestsPerSecond:2,maxConcurrency:1}),{code:'COMMISSIONING_INITIALIZATION_BLOCKED'});
  }
 }finally{assert.equal((await d.runtime.cleanup()).cleaned,true);}
 assert.equal(d.removed(),true);assert.equal(d.calls.filter(a=>Array.isArray(a)&&a[0]==='run').length,1);
});
test('expiry during retained inspection cannot turn stale resources into a valid continuation',async t=>{
 const d=await warmSetup(t),preflight=d.runtime.verify.bind(d.runtime);let now=Date.now();
 t.mock.method(Date,'now',()=>now);t.mock.method(d.runtime,'verify',async (...args)=>{const result=await preflight(...args);now=d.a.expiresAt+1;return result;});
 try{await assert.rejects(d.runtime.verifyRetained(d.next),{code:'ACTIVE_AUTHORIZATION_BLOCKED'});}
 finally{assert.equal((await d.runtime.cleanup()).cleaned,true);}
 assert.equal(d.removed(),true);
});
test('retained scanner changed ownership is never removed by cleanup',async t=>{
 const d=await warmSetup(t),inspect=d.adapter.inspect.bind(d.adapter);
 t.mock.method(d.adapter,'inspect',async(args,kind)=>{const result=await inspect(args,kind);if(args[0]==='5'.repeat(64))result.normalized.labels['cloudsentinel.owner']='foreign';return result;});
 await assert.rejects(d.runtime.verifyRetained(d.next),{code:'ACTIVE_SCANNER_IDENTITY_BLOCKED'});
 const result=await d.runtime.cleanup();assert.equal(result.cleaned,false);assert.equal(d.removed(),false);assert.ok((await fs.stat(d.directory())).isDirectory());
 // Restore the mocked ownership solely to dispose of the offline temporary files.
 d.adapter.inspect=inspect;assert.equal((await d.runtime.cleanup()).cleaned,true);
});
test('retained verification performs one full fresh fixture/gateway check rather than duplicate preflight',async t=>{
 const d=await warmSetup(t);let fixtures=0,namespaces=0;const verify=d.runtime.verifyFixture.bind(d.runtime),binding=require('../services/activeScannerBinding'),before=binding.verify;
 t.mock.method(d.runtime,'preflight',async()=>{throw Error('duplicate preflight');});
 t.mock.method(d.runtime,'verifyFixture',async(...args)=>{fixtures++;return verify(...args);});
 t.mock.method(binding,'verify',async(...args)=>{namespaces++;return before(...args);});
 try{await d.runtime.verifyRetained(d.next);assert.equal(fixtures,1);assert.equal(namespaces,1);await d.runtime.verifyRetained(d.next);assert.equal(fixtures,2);assert.equal(namespaces,2);}
 finally{assert.equal((await d.runtime.cleanup()).cleaned,true);}
});
