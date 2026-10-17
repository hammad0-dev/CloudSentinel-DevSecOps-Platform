'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const f=require('../services/dastFixture'),catalog=require('../config/active-runtime-artifacts.json');
const {operation,normalizeContainerInspect}=require('../services/dockerAdapter');
const image=()=>({Id:catalog.fixture.imageId,Architecture:'amd64',Os:'linux',RootFS:{Layers:[...catalog.fixture.layerDiffIds]},Config:structuredClone(catalog.fixture.expectedConfig)});
const cid='f'.repeat(64),nid='b'.repeat(64),owner='cloudsentinel-s1';
function raw(){return {Id:cid,Name:'/cs-fixture-s1',Image:catalog.fixture.imageId,Config:{...structuredClone(catalog.fixture.expectedConfig),Image:catalog.fixture.imageId,User:'10001:10001',Labels:{'cloudsentinel.owner':owner,'cloudsentinel.scan':'s1','cloudsentinel.role':'fixture'}},State:{Running:true,Health:{Status:'healthy'}},HostConfig:{NetworkMode:nid,ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],SecurityOpt:['no-new-privileges:true'],Memory:268435456,NanoCpus:1000000000,PidsLimit:64,Tmpfs:{'/tmp':'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700'},Sysctls:{'net.ipv6.conf.all.disable_ipv6':'1','net.ipv6.conf.default.disable_ipv6':'1'}},Mounts:[],NetworkSettings:{Networks:{fixture:{NetworkID:nid,IPAddress:'172.30.26.2'}},Ports:{}}};}
const options={projectId:18,executionId:3,scanId:'s1',fixtureKind:f.PYTHON_KIND,host:'fixture.test',port:18080,networkId:nid};
function adapter(change=()=>{}){const calls=[];return {calls,async run(args){calls.push(args);if(args[0]==='image')return {exitCode:0,stderr:'',stdout:JSON.stringify([image()])};if(args[0]==='inspect'){const value=raw();change(value);return {exitCode:0,stderr:'',stdout:JSON.stringify(value)};}return {exitCode:0,stderr:'',stdout:cid};},async inspect(args,kind){if(kind==='network')return {normalized:{id:nid,name:'fixture',internal:true,ipv6:false,subnet:'172.30.26.0/28',gateway:'172.30.26.1',labels:{'cloudsentinel.owner':'cloudsentinel-123456789abc','cloudsentinel.scan':'s1','cloudsentinel.project':'18','cloudsentinel.execution':'3','cloudsentinel.role':'fixture'}}};const value=raw();change(value);return {normalized:normalizeContainerInspect(value)};}};}
test('verified local artifact is registered without asserting ZAP or namespace readiness',()=>{
 assert.equal(catalog.fixture.imageId,'sha256:7a76c5a6a58a677bdf967ed082660bf3e4d2e87800daa618a4882dfbd2e86ff4');
 assert.equal(catalog.fixture.validation.scannerContainmentVerified,false);assert.equal(catalog.zap.capabilities,null);assert.equal(catalog.containmentAdapterValidated,false);
 assert.throws(()=>require('../services/activeRuntimeArtifacts').assertReady(),{code:'ACTIVE_RUNTIME_BLOCKED'});
 assert.doesNotThrow(()=>f.verifyPythonImage(image()));
 for(const mutate of [v=>v.Id='sha256:'+'a'.repeat(64),v=>v.Architecture='arm64',v=>v.Config.User='0',v=>v.Config.Env.push('BAD=1'),v=>v.RootFS.Layers.pop(),v=>v.Config.Entrypoint=['bad']]){const value=image();mutate(value);assert.throws(()=>f.verifyPythonImage(value));}
 const value=image();delete value.Config.Cmd;assert.doesNotThrow(()=>f.verifyPythonImage(value));value.Config.Cmd=['bad'];assert.throws(()=>f.verifyPythonImage(value));
});
test('allowlist accepts immutable local IDs only, never mutable tags or image mutation',()=>{
 assert.doesNotThrow(()=>operation(['image','inspect',catalog.fixture.imageId]));
 for(const args of [['image','inspect',catalog.fixture.localTag],['image','load','local'],['image','pull',catalog.fixture.imageId]])assert.throws(()=>operation(args));
 assert.equal(normalizeContainerInspect(raw()).imageId,catalog.fixture.imageId);
});
test('Python provisioning verifies image first, no mounts/ports, fixed UID and tmpfs, owned membership',async()=>{
 const a=adapter(),resource=await f.provision(a,options);assert.equal(a.calls[0][0],'image');assert.equal(resource.fixtureKind,f.PYTHON_KIND);assert.equal(resource.ip,'172.30.26.2');
 const run=a.calls.find(x=>x[0]==='run');assert.equal(run.at(-1),catalog.fixture.imageId);assert.equal(run[run.indexOf('--user')+1],'10001:10001');assert.ok(run.includes(f.PYTHON_TMPFS||'/tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700'));assert.ok(!run.includes('--mount')&&!run.includes('--publish'));
 assert.equal((await f.cleanup(a,resource)).cleaned,true);assert.ok(a.calls.some(x=>x[0]==='rm'));
});
test('unauthorized origin, Project 17 or unknown kind block before creation',async()=>{
 for(const changed of [{projectId:17},{projectId:'18'},{host:'example.com'},{port:80},{fixtureKind:'arbitrary'}]){const a=adapter();await assert.rejects(f.provision(a,{...options,...changed}));assert.ok(!a.calls.some(x=>x[0]==='run'));}
});
test('image absence and mismatches prevent creation',async()=>{
 const a=adapter();a.run=async()=>{throw Object.assign(Error('missing'),{code:'MISSING_RESOURCE'});};await assert.rejects(f.provision(a,options));
 const b=adapter(),base=b.run.bind(b);b.run=async args=>args[0]==='image'?{exitCode:0,stderr:'',stdout:JSON.stringify([{...image(),Id:'sha256:'+'a'.repeat(64)}])}:base(args);await assert.rejects(f.provision(b,options));assert.equal(b.calls.length,0);
});
test('runtime and membership failures retain created resource for ownership-safe cleanup',async()=>{
 for(const change of [v=>v.Config.User='0',v=>v.HostConfig.Memory=1,v=>v.HostConfig.Tmpfs={},v=>v.HostConfig.PortBindings={'18080/tcp':[{}]},v=>v.NetworkSettings.Networks.extra={},v=>v.NetworkSettings.Networks.fixture.NetworkID='c'.repeat(64),v=>v.State.Health.Status='unhealthy']){
  const a=adapter(change);let created;await assert.rejects(f.provision(a,{...options,onCreated:r=>{created=r;}}));assert.equal(created.id,cid);
 }
 const a=adapter(v=>v.Config.Labels['cloudsentinel.owner']='foreign');await assert.rejects(f.cleanup(a,{id:cid,owner}));assert.ok(!a.calls.some(x=>x[0]==='rm'));
});
test('Active lifecycle selects exact path policy and cleans Python after observation failure',async()=>{
 const {mockDocker}=require('./helpers/runtimeDocker'),d=mockDocker(),Gateway=require('../services/dastGateway').SecureGatewayLifecycle;
 const run=d.adapter.run.bind(d.adapter);d.adapter.run=async args=>args[0]==='image'?{exitCode:0,stderr:'',stdout:JSON.stringify([image()])}:run(args);
 let selected,cleaned=false;
 const fixture={async provision(a,o){assert.equal(o.fixtureKind,f.PYTHON_KIND);return {id:cid,ip:'172.30.26.2',networkId:d.ids.fixture,fixtureKind:f.PYTHON_KIND};},async cleanup(){cleaned=true;return {cleaned:true,residual:[]};}};
 const policy=require('../services/squidPolicy');
 const observation={bindAcceptanceClient(){},clearAcceptanceClient(){},async collectActiveFixture(){throw Object.assign(Error('mock verification stop'),{code:'ACTIVE_NAMESPACE_BLOCKED'});},async collect(){throw Error('Nginx matrix must not run');}};
 const lifecycle=new Gateway({adapter:d.adapter,networks:{async create(){return {networks:d.refs};},async cleanup(){return {residual:[]};}},fixture,observation,policyService:{...policy,async stagePolicy(input){selected=input;return policy.stagePolicy(input);}}});
 await assert.rejects(lifecycle.provision({projectId:18,executionId:3,scanId:'s1',fixtureKind:f.PYTHON_KIND,target:{hostname:'fixture.test',port:18080}}));
 assert.equal(selected.profile,'active');assert.equal(cleaned,true);assert.equal(lifecycle.resources.size,0);
 const gatewayRun=d.calls.find(args=>args[0]==='run'&&args.includes(require('../services/dastGateway').IMAGE));
 const tmpfs=gatewayRun.flatMap((v,i)=>v==='--tmpfs'?[gatewayRun[i+1]]:[]);
 assert.ok(gatewayRun.includes('--read-only'));
 assert.ok(tmpfs.includes(`/tmp:rw,noexec,nosuid,uid=${process.getuid()},gid=${process.getgid()},mode=0700,size=16m`));
 assert.match(selected.target?policy.activePolicy(selected.target):selected.policy||'',/access_log stdio:\/tmp\/cloudsentinel-active-access\.log/);
});
test('enrollment cannot write targets/grants while capability catalog is blocked',async()=>{
 const pool={connect(){throw Error('must not reach database');}};
 await assert.rejects(require('../services/activeRuntimeRegistry').enroll(pool,{projectId:18,executionId:3,userId:7},{}),{code:'ACTIVE_RUNTIME_BLOCKED'});
});
test('Active collector requires exact policy and all path/isolation cases without attesting ZAP',async t=>{
 const {mockDocker}=require('./helpers/runtimeDocker'),d=mockDocker(),client=require('../services/dastAcceptanceClient');
 const resource=await client.provision(d.adapter,{scanId:'s1',networkId:d.ids.scanner,networkReference:d.refs[0]});
 const {RuntimeObservation,runtimeReady}=require('../services/runtimeObservation'),o=new RuntimeObservation({adapter:d.adapter});o.bindAcceptanceClient(client,resource);
 const target={hostname:'fixture.test',ip:'172.30.26.2',port:18080,proxy:'http://172.30.25.3:3128'},policy=require('../services/squidPolicy').activePolicy(target),seen=[];
 d.state.digest=require('crypto').createHash('sha256').update(policy).digest('hex');
 const input={projectId:18,executionId:3,scanId:'s1',gatewayContainerId:d.ids.gateway,scannerContainerId:resource.id,scannerNetworkId:d.ids.scanner,fixtureNetworkId:d.ids.fixture,networkReferences:d.refs,target,stagedPolicy:{containerPath:'/etc/squid/cloudsentinel/squid.conf',policy,policyDigest:'sha256:'+d.state.digest}};
 t.mock.method(client,'probe',async(a,c,kind,destination,options)=>{seen.push({kind,destination,options});return {sourceId:resource.id,complete:true,exitCode:0,actual:options.expected};});
 const evidence=await o.collectActiveFixture(input);assert.equal(evidence.profile,'active');assert.equal(evidence.namespaceScope,'ACCEPTANCE_CLIENT_ONLY');assert.equal(runtimeReady(evidence),false);
 assert.deepEqual(evidence.probes.map(x=>x.name),['positive-sqli','positive-xss','negative-proxy','negative-connect','negative-direct-bypass','negative-path','negative-redirect-path','negative-alternate-host','negative-port','negative-public','negative-metadata','negative-ipv6-bypass']);
 assert.equal(seen[0].options.path,'/test/sqli');assert.equal(seen[1].options.path,'/test/xss');assert.ok(seen.find(x=>x.options.path==='/redirect/host').options.strictPolicy);
 await assert.rejects(o.collectActiveFixture({...input,stagedPolicy:{...input.stagedPolicy,policy:'allow all'}}),{code:'POLICY_NOT_ACTIVE'});
 t.mock.method(client,'probe',async()=>({sourceId:resource.id,complete:false,exitCode:28,actual:'INCONCLUSIVE'}));
 await assert.rejects(o.collectActiveFixture(input),{code:'PROBE_INCONCLUSIVE'});
});
test('known Active rule IDs normalize SQLi/XSS to CWE-89/CWE-79',()=>{
 const {normalize}=require('../services/module2ActiveDast');const a={hostname:'fixture.test',port:18080};
 const findings=normalize({site:[{alerts:[{pluginid:'40018',name:'SQLi',riskcode:'3',instances:[{uri:'http://fixture.test:18080/test/sqli'}]},{pluginid:'40012',name:'XSS',riskcode:'3',instances:[{uri:'http://fixture.test:18080/test/xss'}]}]}]},a);
 assert.deepEqual(findings.map(f=>[f.classification,f.cwe_id]),[['SQLI',89],['XSS',79]]);
 assert.throws(()=>normalize({site:[{alerts:[{pluginid:'40018',instances:[{uri:'http://external.test/test/sqli'}]}]}]},a),{code:'ACTIVE_REPORT_OUT_OF_SCOPE'});
});
test('offline enrollment binds fresh fixture identity to authenticated execution and rolls back rejection',async t=>{
 // Explicitly mocked provenance gates: this test never establishes containment.
 t.mock.method(require('../services/activeRuntimeArtifacts'),'assertReady',()=>catalog);
 t.mock.method(require('../services/dockerAdapter'),'isRuntimeAdapter',()=>true);
 t.mock.method(require('../services/runtimeObservation'),'runtimeReady',()=>true);
 t.mock.method(require('../services/ownedDockerNetworks'),'inspectOwnedNetwork',async()=>({id:nid,name:'fixture'}));
 const Gateway=require('../services/dastGateway').SecureGatewayLifecycle;
 for(const authorized of [true,false]) {
  const a=adapter(),lifecycle=new Gateway({adapter:a}),calls=[];
  const original=a.run.bind(a);a.run=async args=>args[0]==='image'&&args[2]===catalog.zap.reference?{exitCode:0,stderr:'',stdout:JSON.stringify([{Id:catalog.zap.imageId,Architecture:'amd64',Os:'linux',Config:catalog.zap.config,RootFS:{Layers:catalog.zap.layerDiffIds},RepoDigests:[catalog.zap.reference]}])}:original(args);
  lifecycle.states.set('s1','READY');lifecycle.resources.set('s1',{fixtureResource:{id:cid,owner,scanId:'s1',networkId:nid,fixtureKind:f.PYTHON_KIND},owned:{networks:[{id:nid}]},runtimeObservation:{profile:'active',projectId:18,executionId:3,scanId:'s1',scannerNetworkId:'c'.repeat(64),target:{hostname:'fixture.test',ip:'172.30.26.2',port:18080}}});
  // Registration additionally requires the scanner membership reference.
  lifecycle.resources.get('s1').owned.networks.push({id:'c'.repeat(64)});
  const db={async query(sql,params){calls.push({sql,params});return {rows:sql.startsWith('SELECT o.')&&authorized?[{user_id:7}]:[]};},release(){}};
  const promise=require('../services/activeRuntimeRegistry').enroll({async connect(){return db;}},{projectId:18,executionId:3,userId:7},{lifecycle,adapter:a,scanId:'s1'});
  if(authorized){const result=await promise;assert.match(result.targetId,/^[a-f0-9-]{36}$/);const insert=calls.find(c=>c.sql.startsWith('INSERT'));assert.deepEqual(insert.params.slice(1,5),[18,3,cid,'c'.repeat(64)]);assert.equal(calls.at(-1).sql,'COMMIT');}
  else{await assert.rejects(promise);assert.equal(calls.at(-1).sql,'ROLLBACK');assert.ok(!calls.some(c=>c.sql.startsWith('INSERT')));}
 }
});
test('artifact availability rejects an absent replacement ZAP instead of trusting its catalog record',async()=>{
 const calls=[];const adapter={async run(args){calls.push(args);throw Object.assign(Error('not present'),{code:'MISSING_RESOURCE'});}};
 await assert.rejects(require('../services/activeRuntimeArtifacts').verifyAvailable(adapter,catalog),{code:'MISSING_RESOURCE'});
 assert.deepEqual(calls,[['image','inspect',catalog.zap.reference],['image','inspect',catalog.fixture.reference]]);
});
