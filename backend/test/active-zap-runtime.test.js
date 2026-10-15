'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs/promises'),path=require('path');
const {ActiveZapRuntime,capabilities,proxyPolicy,runArguments}=require('../services/activeZapRuntime');
const {mockDocker}=require('./helpers/runtimeDocker');
function catalog(){const entry=(name,id)=>({reference:`${name}@sha256:${id.repeat(64)}`,imageId:'sha256:'+id.repeat(64),architecture:'amd64',os:'linux'});const zap=entry('zap/test','a'),fixture={...entry('fixture/test','b'),fixtureKind:'cloudsentinel-vulnerable-v1'};zap.capabilities={initialization:require('./helpers/zapInitializationEvidence')(zap.imageId),verified:true,runtimeContract:{apiBinding:'LOOPBACK_ONLY',apiAuthentication:'REQUIRED',maxRequestsPerSecond:2,maxConcurrency:1,spiderRateLimited:true,exactPathScope:true,jobCompletionVerified:true,timeoutVerified:true,cancellationVerified:true,exportFormat:'traditional-json',evidenceSha256:'e'.repeat(64)},imageId:zap.imageId,activeRuleIds:require('../config/zap-active-policy-v1.json').approvedPluginIds,commands:['automation','spider','activeScan','report','proxy','rateLimit','sha256sum','python3']};return {zap,fixture};}
async function setup(t,scenario='ok'){
  const old=process.env.NODE_ENV,flag=process.env.DAST_ACTIVE_ENABLED;process.env.NODE_ENV='test';process.env.DAST_ACTIVE_ENABLED='true';t.after(()=>{if(old===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=old;if(flag===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=flag;});
  const d=mockDocker(),c=catalog(),fixtureId='f'.repeat(64),scannerId='5'.repeat(64),a={hostname:'fixture.test',ip:'172.30.26.2',port:18080,fixtureContainerId:fixtureId,scannerNetworkId:d.ids.scanner};let directory,removed=false;
  const resources={fixtureResource:{id:fixtureId,networkId:d.ids.fixture},acceptanceClientId:d.ids.client,runtimeObservation:{verification:'RUNTIME_OBSERVED',complete:true,independent:true,scannerContainerId:d.ids.client,scannerNetworkId:d.ids.scanner,ipv6:false,directTcpBypass:false,routes:{ipv4:[],ipv6:[],addresses:[]}},gatewayId:d.ids.gateway,owned:{networks:d.refs},staged:{containerPath:'/etc/squid/cloudsentinel/squid.conf'}};
  const lifecycle={resources:new Map([['s1',resources]]),async cleanup(){d.calls.push(['lifecycle-cleanup']);return {state:'CLEANED',residual:[]};}};
  const inspect=d.adapter.inspect.bind(d.adapter),run=d.adapter.run.bind(d.adapter);
  d.adapter.inspect=async(args,kind)=>{
    if(kind==='container'&&[fixtureId,scannerId].includes(args[0])){
      const fixture=args[0]===fixtureId;const n={objectId:args[0],imageDigest:fixture?c.fixture.reference:c.zap.reference,state:{Running:true},labels:{'cloudsentinel.owner':scenario==='owner'?'foreign':'cloudsentinel-s1','cloudsentinel.role':fixture?'fixture':'active-zap'},networks:fixture?{'cs-fixture':{NetworkID:d.ids.fixture,IPAddress:scenario==='dns'?'172.30.26.9':a.ip}}:d.state.clientNetworks,security:{readOnly:true,privileged:false,capAdd:[],capDrop:['ALL'],securityOpt:['no-new-privileges:true']},mounts:fixture?[]:[{Source:directory,Destination:'/zap/wrk',RW:false}]};
      if(scenario==='image'&&fixture)n.imageDigest=c.zap.reference;
      return {normalized:n};
    }return inspect(args,kind);
  };
  d.adapter.run=async args=>{
    if(args[0]==='image'){const image=[c.zap,c.fixture].find(i=>i.reference===args[2]);return {exitCode:0,stderr:'',stdout:JSON.stringify([{Id:image.imageId,Architecture:image.architecture,Os:image.os,RepoDigests:[image.reference]}])};}
    if(args[0]==='run'){d.calls.push(args);directory=args[args.indexOf('--mount')+1].split('src=')[1].split(',')[0];return {stdout:scannerId,exitCode:0,stderr:''};}
    if(args[0]==='inspect'&&args.at(-1)===fixtureId)return {stdout:JSON.stringify({HostConfig:{PortBindings:scenario==='published'?{'18080/tcp':[{}]}:{}},NetworkSettings:{Ports:{}}}),stderr:'',exitCode:0};
    if(args[0]==='exec'&&args[1]===d.ids.gateway&&args[2]==='cat')return {stdout:scenario==='policy'?'allow all':proxyPolicy(a),stderr:'',exitCode:0};
    if(args[0]==='exec'&&args[1]===scannerId){d.calls.push(args);if(args[2]==='ip')return {stdout:args.includes('address')?d.state.addresses:args.includes('inet6')?'':d.state.route,stderr:'',exitCode:0};if(args[2]==='sha256sum'){const file=path.join(directory,path.basename(args[3]));return {stdout:require('crypto').createHash('sha256').update(await fs.readFile(file)).digest('hex')+'  '+args[3]+'\n',stderr:'',exitCode:0};}if(args[2]==='zap.sh')return {exitCode:scenario==='interrupted'?1:0,stdout:scenario==='storage'?'java.io.IOException: No space left on device':scenario==='policy-init'?'SAXParseException: Premature end of file':'jobs finished',stderr:''};if(args[2]==='cat')return {exitCode:0,stderr:'',stdout:scenario==='report'?'{}':JSON.stringify({site:[]})};}
    if(['stop','rm'].includes(args[0])&&args[1]===scannerId){d.calls.push(args);if(scenario==='cleanup')throw Object.assign(Error('busy'),{code:'BUSY'});if(args[0]==='rm')removed=true;return {stdout:'',stderr:'',exitCode:0};}
    return run(args);
  };
  const runtime=new ActiveZapRuntime({adapter:d.adapter,lifecycle,scanId:'s1',catalog:c,offline:true});
  return {...d,runtime,a,c,removed:()=>removed,directory:()=>directory};
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
  try{await d.runtime.verify(session,d.a);const plans=require('../services/module2ActiveDast').ROUTES.map(p=>require('../services/dastActiveScanner').automationPlan(`http://fixture.test:18080${p}`));const result=await d.runtime.scan(session,{plans,maxRequestsPerSecond:2,maxConcurrency:1});assert.equal(result.completed,true);assert.equal(d.calls.filter(a=>a[2]==='zap.sh').length,2);assert.ok(d.calls.filter(a=>a[2]==='zap.sh').every(a=>a.includes('connection.proxyChain.hostName=172.30.25.3')&&a.includes('-Xmx512m')&&a[a.indexOf('-dir')+1]==='/home/zap/.ZAP'));}finally{assert.equal((await d.runtime.cleanup(session)).cleaned,true);}assert.equal(d.removed(),true);await assert.rejects(fs.stat(d.directory()),{code:'ENOENT'});
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
