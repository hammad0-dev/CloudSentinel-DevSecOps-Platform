'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs/promises');
const {ZapContainmentDiagnostic,validate,verifyZapImage,listeners}=require('../services/zapContainmentDiagnostic');
const fixture=require('../services/dastFixture'),client=require('../services/dastAcceptanceClient'),native=require('../services/nativeConnectArtifact');
const config=require('../config/zap-containment-diagnostic.json'),catalog=require('../config/active-runtime-artifacts.json');
const {DockerAdapter}=require('../services/dockerAdapter'),{SecureGatewayLifecycle,IMAGE:SQUID}=require('../services/dastGateway');
const {RuntimeObservation}=require('../services/runtimeObservation');
const {mockDocker}=require('./helpers/runtimeDocker');
let sequence=0;
const image=()=>({Id:config.imageId,Architecture:'amd64',Os:'linux',Config:structuredClone(config.config),RootFS:{Layers:config.layers}});
async function setup(t,scenario='ok'){
 const old=process.env.NODE_ENV,flag=process.env.DAST_ACTIVE_ENABLED;process.env.NODE_ENV='test';process.env.DAST_ACTIVE_ENABLED='false';
 t.after(()=>{if(old===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=old;if(flag===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=flag;});
 const scope={scope:'zap-python-containment',scanId:'zpd-'+(++sequence),projectId:18,executionId:3,expiresAt:Date.now()+600000};
 if(scenario.startsWith('response-'))scope.commissioningResponse=true;
 if(scenario.startsWith('passive-'))scope.passiveAutorun=true;
 if(scenario.startsWith('active-')){scope.activeDiagnostic=true;scope.activePermit={};t.mock.method(require('../services/activeDiagnosticAuthorization'),'valid',()=>true);t.mock.method(require('../services/activeDiagnosticAuthorization'),'consume',()=>{});}
 const base=mockDocker(),zap='5'.repeat(64),fid='f'.repeat(64),calls=[],state={zap:false,helper:false,fixture:false,directory:null,abort:new AbortController()};
 const refs=base.refs;for(const r of refs){r.scanIdentity.scanId=scope.scanId;Object.assign(r.labels,{'cloudsentinel.owner':'cloudsentinel-123456789abc','cloudsentinel.scan':scope.scanId,'cloudsentinel.project':'18','cloudsentinel.execution':'3','cloudsentinel.role':r.role});}
 const owner='cloudsentinel-'+scope.scanId,labels=role=>({'cloudsentinel.owner':owner,'cloudsentinel.scan':scope.scanId,'cloudsentinel.role':role});
 t.mock.method(native,'stage',async scanId=>({scanId,filePath:'/tmp/mocked-native-connect',mount:'type=bind,src=/tmp/mocked-native-connect,dst=/opt/cloudsentinel/connect-peer,readonly'}));
 t.mock.method(native,'verify',async value=>value);t.mock.method(native,'cleanup',async()=>({cleaned:true,residual:[]}));
 const response=(cb,stdout='',stderr='',code=0)=>cb(code?Object.assign(Error('mock command failure'),{code}):null,stdout,stderr);
 function executor(bin,args,options,cb){
  calls.push(args);
  if(args[0]==='image'){
   let v;
   if(args[2]===config.imageId){v=image();if(scenario==='missing-image')return response(cb,'','No such image',1);if(scenario==='bad-image')v.Id='sha256:'+'9'.repeat(64);}
   else if(args[2]===catalog.fixture.imageId)v={Id:catalog.fixture.imageId,Architecture:'amd64',Os:'linux',Config:catalog.fixture.expectedConfig,RootFS:{Layers:catalog.fixture.layerDiffIds}};
   else v={Id:'sha256:'+'6'.repeat(64),Architecture:'amd64',Os:'linux',RepoDigests:[args[2].split('@')[0].replace(/:[^/:]+$/,'')+'@'+args[2].split('@')[1]]};
   return response(cb,JSON.stringify([v]));
  }
  if(args[0]==='run'&&args.includes(SQUID))state.gatewayArgs=args;
  if(args[0]==='run'&&args.includes(catalog.fixture.imageId)){state.fixture=true;return response(cb,fid);}
  if(args[0]==='run'&&args.includes(config.imageId)){
   state.zap=true;state.zapArgs=args;state.directory=args[args.indexOf('--mount')+1].split('src=')[1].split(',')[0];
   if(scenario==='uncertain-create')return response(cb,'','creation response lost',1);
   return response(cb,zap);
  }
  if(args[0]==='run'&&args.includes(client.IMAGE)){
   state.helper=true;state.helperArgs=args;
   if(scenario==='cancel-helper')state.abort.abort();
   return base.adapter.executor(bin,args,options,scenario==='uncertain-helper'?()=>response(cb,'','creation response lost',1):cb);
  }
  if(args[0]==='inspect'&&(!/^[a-f0-9]{64}$/.test(args.at(-1)))){
   if(args.at(-1)==='cs-zap-'+scope.scanId&&state.zap)args=['inspect','--format','{{json .}}',zap];
   else if(args.at(-1)==='cs-client-'+scope.scanId&&state.helper)args=['inspect','--format','{{json .}}',base.ids.client];
   else return response(cb,'','No such container',1);
  }
  if(args[0]==='inspect'&&[zap,fid].includes(args.at(-1))){
   const z=args.at(-1)===zap;
   if(!(z?state.zap:state.fixture))return response(cb,'','No such container',1);
   const r={Id:z?zap:fid,Name:z?'/cs-zap-'+scope.scanId:'/cs-fixture-'+scope.scanId,Image:z?config.imageId:catalog.fixture.imageId,Config:z?{User:'1000:1000',Image:config.imageId,Labels:labels('zap-containment-diagnostic')}:{...catalog.fixture.expectedConfig,Image:catalog.fixture.imageId,Labels:labels('fixture')},State:{Running:true,Health:{Status:'healthy'}},HostConfig:{NetworkMode:z?base.ids.scanner:base.ids.fixture,ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],CapAdd:[],SecurityOpt:['no-new-privileges:true'],Memory:(z?1536:256)*1048576,NanoCpus:1000000000,PidsLimit:z?128:64,PublishAllPorts:false,Sysctls:{'net.ipv6.conf.all.disable_ipv6':'1','net.ipv6.conf.default.disable_ipv6':'1'},Tmpfs:z?{'/tmp':'rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=1777','/home/zap/.ZAP':'rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700',[require('../config/zap-writable-paths.json').profilePath]:'rw,noexec,nosuid,nodev,size=4m,uid=1000,gid=1000,mode=0700'}:{'/tmp':'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700'}},Mounts:z?[{Type:'bind',Source:state.directory,Destination:'/zap/wrk',RW:false}]:[],NetworkSettings:{Networks:z?base.state.clientNetworks:{'cs-fixture':{NetworkID:base.ids.fixture,IPAddress:'172.30.26.2'}},Ports:{}}};
   if(z)r.HostConfig.Tmpfs=Object.fromEntries(Object.entries(r.HostConfig.Tmpfs).sort());
   if(z&&scenario==='container-exit')r.State={Running:false,ExitCode:137,OOMKilled:true};
   if(z&&scenario==='missing-tmpfs')delete r.HostConfig.Tmpfs['/home/zap/.ZAP'];
   if(z&&scenario==='wrong-owner')r.Config.Labels['cloudsentinel.owner']='foreign';
   if(z&&scenario==='wrong-network')r.NetworkSettings.Networks.extra={};
   return response(cb,JSON.stringify(r));
  }
  if(args[0]==='inspect'&&args.at(-1)===base.ids.gateway){
   return base.adapter.executor(bin,args,options,(e,stdout,stderr)=>{
    const v=JSON.parse(stdout);v.Config.User='1000:1000';v.HostConfig.Memory=268435456;v.HostConfig.NanoCpus=1000000000;v.HostConfig.PidsLimit=64;
    const mount=state.gatewayArgs[state.gatewayArgs.indexOf('--mount')+1];v.Mounts=[{Type:'bind',Source:mount.split('src=')[1].split(',')[0],Destination:'/etc/squid/cloudsentinel/squid.conf',RW:false}];
    return cb(e,JSON.stringify(v).replaceAll('s1',scope.scanId),stderr);
   });
  }
  if(args[0]==='inspect'&&args.at(-1)===base.ids.client){
   return base.adapter.executor(bin,args,options,(e,stdout,stderr)=>{
    if(!state.helper)return response(cb,'','No such container',1);
    const n=JSON.parse(stdout);n.HostConfig.NetworkMode=scenario==='separate-client'?base.ids.scanner:'container:'+zap;n.HostConfig.Memory=134217728;n.HostConfig.NanoCpus=500000000;n.HostConfig.PidsLimit=64;
    n.NetworkSettings.Networks=scenario==='separate-client'?base.state.clientNetworks:{};n.Config.Labels=labels('acceptance-client');return cb(e,JSON.stringify(n),stderr);
   });
  }
  if(args[0]==='exec'&&args[1]===zap){
   if(args.includes(require('../services/zapStartupEvidence').READINESS_ARGS[4])){
    const header='sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n';
    if(['readonly-runtime','missing-policy'].includes(scenario)){const now=Date.now();t.mock.method(Date,'now',()=>now+180001);}
    return response(cb,JSON.stringify({writable:[scenario!=='readonly-runtime',true,true,true],policy:scenario==='missing-policy'?null:{xmlParsed:true,bytes:313,sha256:'a'.repeat(64)},tables:{tcp:header+'0: '+(scenario==='startup-listener'?'00000000':'0100007F')+':1F9A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1\n',tcp6:header,udp:header,udp6:header}}));
   }
   if(args[4]==='/zap/wrk/commissioning-probe.py'){
    if(args[5]==='configure')return response(cb,JSON.stringify({rateConfigured:2,concurrencyConfigured:1}));
    if(args[5]==='stop'){state.daemonStopped=true;return response(cb,JSON.stringify({Result:'OK'}));}
    assert.equal(args[5],'request');const input=JSON.parse(args.slice(6).join(''));state.applicationRequests=(state.applicationRequests||0)+1;
    const url=input.request.split(' ')[1],index=state.applicationRequests-1;
    state.applicationLogs=(state.applicationLogs||'')+`${1700000000+index}.000 172.30.25.2 GET ${url} 200 TCP_MISS/HIER_DIRECT\n`;
    const message={requestHeader:input.request,responseHeader:'HTTP/1.1 200 OK\r\nVia: 1.1 proxy (squid/6.6)\r\n\r\n',responseBody:index===0?'[["demo-one"]]':'<html><body>fixture: hello</body></html>'};
    if(scenario==='response-redirect')message.responseHeader+='Location: http://external.test/\r\n';
    return response(cb,JSON.stringify(scenario==='response-malformed'?{sendRequest:[]}:{sendRequest:[message]}));
   }
   if(args.includes(require('../services/zapStartupEvidence').PROBE)){
    if(scenario==='empty-first-log'&&!state.emptyLogSeen){state.emptyLogSeen=true;return response(cb,JSON.stringify({log:'',logBytes:0,daemonExitCode:null}));}
    if(scenario==='malformed-startup')return response(cb,'not JSON');
    const logs={initialization:'No space left on device',workspace:'ERROR /zap/wrk/session: Read-only file system',addon:'ERROR Failed to load add-on ascanrules',policy:'SAXParseException: Premature end of file',preferences:'BackingStoreException: preferences unusable',binding:'BindException: Address already in use'};
    if(scenario==='genuine-info')logs[scenario]=require('./fixtures/zap-startup-info-false-positive.json').excerpt+'\nExtensions loaded\nZAP is now listening on 127.0.0.1:8090';
    return response(cb,JSON.stringify({log:logs[scenario]||'Extensions loaded\nZAP is now listening on 127.0.0.1:8090',logBytes:(logs[scenario]||'Extensions loaded\nZAP is now listening on 127.0.0.1:8090').length,daemonExitCode:scenario==='early-exit'?2:state.daemonStopped?0:null}));
   }
   if(args.includes('os.readlink'))return response(cb,'net:[12345]\n');
   if(args.includes("import os;print(os.readlink('/proc/self/ns/net'))"))return response(cb,'net:[12345]\n');
   if(args.includes('python3')&&args.some(a=>a.includes('urllib.request,json,sys'))){
    if(args.includes('core/view/version')){
     if(scenario==='api-timeout'){const now=Date.now();t.mock.method(Date,'now',()=>now+180001);return response(cb,'','API unavailable',1);}
     return response(cb,JSON.stringify({version:'2.17.0'}));
    }
    if(args.includes('autoupdate/view/installedAddons'))return response(cb,JSON.stringify({installedAddons:[...Object.entries(require('../services/zapInitialization').expectedAddons).map(([id,version])=>({id,version,installationStatus:'INSTALLED'})),...(scope.passiveAutorun&&scenario!=='passive-no-addon'?[{id:'pscan',version:'0.6.0',installationStatus:'INSTALLED'}]:[])]}));
    if(args.includes('ascan/view/scanners'))return response(cb,JSON.stringify({scanners:require('../config/zap-active-policy-v1.json').approvedPluginIds.map(id=>({id}))}));
   }
   if(args[2]==='cat'&&args.at(-1)==='/tmp/commissioning-plan-0.exit')return response(cb,'0\n');
   if(args[2]==='cat'&&args.at(-1)==='/tmp/commissioning-plan-0.log')return response(cb,scenario==='passive-unknown'?'Unknown Automation output':scenario==='passive-error'?'42 [ZAP] ERROR org.example - initialization failed':scenario==='passive-malformed'?'Job report started\0':scenario.startsWith('active-')?'Job activeScan started\nJob activeScan finished, time taken: 00:00:01\nAutomation plan succeeded!':'Job requestor started\nJob requestor finished, time taken: 00:00:01\nAutomation plan succeeded!');
   if(args[2]==='cat'&&args.at(-1)==='/tmp/report-0.json')return response(cb,scenario==='passive-bad-report'?'{}':JSON.stringify({site:[{'@name':scenario==='passive-escape'?'http://external.test':'http://'+scope.scanId+'.test:18080',alerts:[]}]}));
   if(args[2]==='cat')return response(cb,scenario==='initialization'?'No space left on device':'ZAP initialized');
   return response(cb);
  }
  if(args[0]==='exec'&&args.includes('-d')){if(args.includes('commissioning-plan')){state.planRuns=(state.planRuns||0)+1;const forwarded=args.slice(args.indexOf('commissioning-plan')+1);assert.equal(forwarded[0],'-cmd');assert(!forwarded.includes('zap.sh'));assert.equal(forwarded.at(-1),'/zap/wrk/plan-0.yaml');}return scenario==='invalid-command'?response(cb,'','zap.sh: not found',127):response(cb);}
  if(args[0]==='exec'&&args[1]===base.ids.client){
   if(args[2]==='readlink'&&scenario==='unsupported-helper')return response(cb,'','readlink: not found',127);
   if(args[2]==='readlink'&&scenario==='empty-namespace')return response(cb,'');
   if(args[2]==='readlink')return response(cb,scenario==='wrong-inode'?'net:[54321]\n':'net:[12345]\n');
   if(args[2]==='cat'){
    const header='  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n';
    return response(cb,['tcp6','udp','udp6'].includes(args.at(-1).split('/').at(-1))?header:header+'0: '+(scenario==='listener'?'00000000':'0100007F')+':1F9A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1\n');
   }
   if(args[2]==='/opt/cloudsentinel/connect-peer')return response(cb,JSON.stringify({schemaVersion:1,connected:true,peerIp:'172.30.25.3',peerPort:3128,requestedAuthority:scope.scanId+'.test:18080',headersValid:true,responseStatus:403,squidServer:true,accessDenied:true,error:null,complete:true}));
   if(args[2]==='nc')return scenario==='direct-success'?response(cb):response(cb,'','nc: Network unreachable',1);
   if(args.at(-1).startsWith('http')){
    const u=new URL(args.at(-1)),good=u.hostname===scope.scanId+'.test'&&u.port==='18080'&&['/test/sqli','/test/xss'].includes(u.pathname);
    if(scenario==='cancel-probe')state.abort.abort();
    if(scenario==='expire-probe')t.mock.method(Date,'now',()=>scope.expiresAt+1);
    if(good){const body=u.pathname==='/test/sqli'?'[["demo-one"]]':'<html><body>fixture: hello</body></html>';return response(cb,(args[args.indexOf('--output')+1]==='-'?body+'|CS_ZPD|':'')+'200 000 172.30.25.3','HTTP/1.1 200 OK\r\n\r\n');}
    return response(cb,scenario==='proxy-escape'?'200 000 172.30.25.3':'403 000 172.30.25.3','HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n');
   }
  }
  if(['stop','rm'].includes(args[0])&&[zap,fid,base.ids.client].includes(args.at(-1))){
   if(scenario==='cleanup'&&args.at(-1)===base.ids.client)return response(cb,'','busy',1);
   if(args[0]==='rm'){if(args.at(-1)===zap)state.zap=false;else if(args.at(-1)===fid)state.fixture=false;else state.helper=false;}
   return response(cb);
  }
  if(args[0]==='exec'&&args[1]===base.ids.gateway&&args[2]==='cat'&&args.at(-1)==='/tmp/cloudsentinel-active-access.log')return response(cb,state.applicationLogs||'');
  if(args[0]==='exec'&&args[1]===base.ids.gateway&&args[2]==='cat'&&args.at(-1)==='/etc/squid/cloudsentinel/squid.conf')return response(cb,base.state.policy);
  if(args[0]==='exec'&&args[1]===base.ids.gateway&&args[2]==='sha256sum')return response(cb,base.state.digest+'  /etc/squid/cloudsentinel/squid.conf');
  return base.adapter.executor(bin,args,options,(e,stdout,stderr)=>cb(e,stdout?.replaceAll('s1',scope.scanId),stderr));
 }
 if(scenario==='ipv4')base.state.route='default via 172.30.25.1 dev eth0\n';
 if(scenario==='ipv6')base.state.ipv6='::/0 dev eth0\n';
 const adapter=new DockerAdapter({executor}),policy=require('../services/squidPolicy');
 const lifecycle=new SecureGatewayLifecycle({adapter,networks:{async create(){return {networks:refs};},async cleanup(){calls.push(['owned-network-cleanup']);return {residual:[]};}},observation:new RuntimeObservation({adapter}),policyService:{...policy,async stagePolicy(o){const s=await policy.stagePolicy(o);base.state.digest=s.policyDigest.slice(7);base.state.policy=s.policy;return s;}}});
 t.after(async()=>{for(const r of lifecycle.resources.values()){if(r.staged?.directory)await fs.rm(r.staged.directory,{recursive:true,force:true});}});
 const diagnostic=new ZapContainmentDiagnostic({adapter,lifecycle,input:scope,offline:true});
 return {diagnostic,calls,state,scope,adapter,lifecycle};
}
test('empty initial startup log remains pending until positive initialization, without restarting daemon',async t=>{
 const d=await setup(t,'empty-first-log'),r=await d.diagnostic.run();assert.equal(d.state.emptyLogSeen,true);assert.equal(r.status,'PASS',JSON.stringify(r));assert.equal(r.cleanup.cleaned,true);assert.equal(d.calls.filter(a=>a[0]==='exec'&&a.includes('-d')).length,1);
});
test('diagnostic scope rejects arbitrary images, URLs, operations, Project 17 and expiry',()=>{
 const input={scope:'zap-python-containment',scanId:'pure-1',projectId:18,executionId:1,expiresAt:Date.now()+10000};assert.doesNotThrow(()=>validate(input));
 for(const changed of [{target:'http://external'},{image:'tag'},{action:'scan'},{projectId:17},{expiresAt:0},{scope:'active-scan'}])assert.throws(()=>validate({...input,...changed}));
 assert.doesNotThrow(()=>verifyZapImage(image()));const bad=image();bad.Config.User='root';assert.throws(()=>verifyZapImage(bad));
});
test('complete mocked shared-ZAP diagnostic emits no scan jobs and always cleans',async t=>{
 const d=await setup(t);const r=await d.diagnostic.run();assert.equal(r.status,'PASS',JSON.stringify(r));assert.equal(typeof d.diagnostic.command,'undefined');assert.equal(typeof d.diagnostic.startDaemon,'undefined');assert.equal(typeof d.diagnostic.benignResponses,'undefined');assert.equal(r.fullContainment,false);assert.equal(r.containmentReady,false);assert.equal(r.zapApplicationRequests,false);assert.equal(r.verification,'MOCK_ONLY_NOT_VERIFIED');assert.equal(r.namespaceEvidence.zapContainerId,'5'.repeat(64));assert.equal(r.cleanup.cleaned,true);assert.equal(d.state.zap,false);assert.equal(d.state.helper,false);assert.equal(d.state.fixture,false);
 assert.ok(d.calls.some(a=>a.includes('container:'+'5'.repeat(64))));assert.ok(d.calls.some(a=>a.includes('-daemon')));assert.ok(!d.calls.flat().some(a=>['-autorun','-quickurl','-spider'].includes(a)||/\/action\//.test(a)));assert.ok(!d.calls.some(a=>a[0]==='image'&&a[1]!=='inspect'));
 assert.equal(process.env.DAST_ACTIVE_ENABLED,'false');assert.throws(()=>require('../services/activeRuntimeArtifacts').assertReady(),{code:'ACTIVE_RUNTIME_BLOCKED'});assert.equal(require('../services/squidPolicy').activePolicy({hostname:'fixture.test',ip:'172.30.26.2',port:18080}).includes('^/test/(sqli|xss)'),true);
 await assert.rejects(d.diagnostic.run(),{code:'DIAGNOSTIC_ALREADY_ATTEMPTED'});
});
test('incorrect image, owner, membership, namespace, route, connectivity and listeners fail closed',async t=>{
 for(const scenario of ['missing-image','bad-image','wrong-owner','wrong-network','separate-client','wrong-inode','direct-success','proxy-escape','ipv4','ipv6','listener','initialization','uncertain-create','uncertain-helper','unsupported-helper','empty-namespace']){
  const d=await setup(t,scenario),r=await d.diagnostic.run();assert.notEqual(r.status,'PASS',scenario+' '+JSON.stringify(r));assert.equal(r.containmentReady,false);
  if(scenario!=='wrong-owner')assert.equal(r.cleanup.cleaned,true,scenario+' '+JSON.stringify(r));
  else{assert.equal(r.cleanup.cleaned,false);assert.equal(d.state.zap,true);await fs.rm(d.state.directory,{recursive:true,force:true});}
 }
});
test('cancellation and expiration remain non-success and preserve ownership cleanup',async t=>{
 for(const scenario of ['cancel-helper','cancel-probe']){const d=await setup(t,scenario),r=await d.diagnostic.run({signal:d.state.abort.signal});assert.notEqual(r.status,'PASS');assert.equal(r.reason,'DIAGNOSTIC_CANCELLED');assert.equal(r.cleanup.cleaned,true,JSON.stringify(r));}
 const d=await setup(t);t.mock.method(Date,'now',()=>d.scope.expiresAt+1);const r=await d.diagnostic.run();assert.notEqual(r.status,'PASS');assert.equal(r.reason,'DIAGNOSTIC_EXPIRED');assert.equal(r.cleanup.cleaned,true);
});
test('cleanup failure cannot report diagnostic success or remove a live helper mount',async t=>{
 const d=await setup(t,'cleanup'),r=await d.diagnostic.run();assert.equal(r.status,'FAIL');assert.equal(r.cleanup.cleaned,false);assert.equal(d.state.zap,true);assert.ok(!d.calls.some(a=>a[0]==='rm'&&a.at(-1)==='5'.repeat(64)));
 await fs.rm(d.state.directory,{recursive:true,force:true});
});
test('listener parsing rejects missing, malformed and IPv4/IPv6 wildcard observations',()=>{
 const h='sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n';
 const row=(address,remote,state='0A')=>`0: ${address}:1F9A ${remote}:0000 ${state} 00000000:00000000 00:00000000 00000000 1000 0 1\n`;
 assert.equal(listeners(h+row('0100007F','00000000'),4)[0].port,8090);
 assert.equal(listeners(h+row('00000000000000000000000001000000','0'.repeat(32)),6)[0].loopback,true);
 assert.equal(listeners(h+row('0100007F','00000000','07'),4,'udp')[0].protocol,'udp');
 for(const [text,family] of [['',4],['unknown header',4],[h+'truncated',4],[h+row('00000000','00000000'),4],[h+row('0'.repeat(32),'0'.repeat(32)),6]])assert.throws(()=>listeners(text,family));
});
test('scope cannot be reused for a different origin, execution or diagnostic action',async t=>{
 const d=await setup(t);const input={...d.scope,fixtureKind:fixture.PYTHON_KIND,nativeConnect:true,mode:'full',diagnosticScope:d.diagnostic.scope,target:{hostname:d.scope.scanId+'.test',port:18080}};
 for(const change of [{projectId:19},{executionId:4},{target:{hostname:'external.test',port:18080}},{mode:'connect-diagnostic'}])await assert.rejects(d.lifecycle.provision({...input,...change}),{code:'INVALID_DIAGNOSTIC_SCOPE'});
 await assert.rejects(d.diagnostic.run({action:'scan'}),{code:'INVALID_DIAGNOSTIC_SCOPE'});
 await assert.rejects(d.diagnostic.api('ascan/action/scan'),{code:'DIAGNOSTIC_ACTION_FORBIDDEN'});assert.equal(d.calls.length,0);
 const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='true';assert.throws(()=>validate({...d.scope,scanId:'different'}));process.env.DAST_ACTIVE_ENABLED=old;
});
test('CLI without explicit execution scope exits nonzero and remains inert',()=>{
 const result=require('child_process').spawnSync(process.execPath,[require.resolve('../scripts/zap-containment-diagnostic')],{encoding:'utf8',env:{...process.env,DAST_ACTIVE_ENABLED:'false'}});
 assert.equal(result.status,1);assert.equal(JSON.parse(result.stderr).reason,'EXPLICIT_DIAGNOSTIC_SCOPE_REQUIRED');
});
test('sanitized diagnostic artifacts are unique and owner restricted',async()=>{
 const save=require('../scripts/zap-containment-diagnostic').saveEvidence;
 const a=await save({diagnosticOnly:true,containmentReady:false}),b=await save({diagnosticOnly:true});
 try{assert.notEqual(a,b);assert.equal((await fs.stat(a)).mode&511,448);assert.equal((await fs.stat(a+'/sanitized-report.json')).mode&511,384);}finally{await fs.rm(a,{recursive:true,force:true});await fs.rm(b,{recursive:true,force:true});}
});
test('daemon version alone, missing rules and duplicate loaded add-ons never establish readiness',()=>{
 const {daemonViews}=require('../services/zapContainmentDiagnostic');
 const addons={installedAddons:Object.entries(require('../services/zapInitialization').expectedAddons).map(([id,version])=>({id,version,installationStatus:'INSTALLED'}))},rules={scanners:require('../config/zap-active-policy-v1.json').approvedPluginIds.map(id=>({id}))};
 assert.doesNotThrow(()=>daemonViews({version:'2.17.0'},addons,rules));
 assert.throws(()=>daemonViews({version:'2.17.0'},{installedAddons:[]},rules),{code:'DIAGNOSTIC_ADDONS_NOT_READY'});
 assert.throws(()=>daemonViews({version:'2.17.0'},addons,{scanners:[{id:'90026'}]}),{code:'DIAGNOSTIC_RULES_NOT_READY'});
 const duplicate=structuredClone(addons);duplicate.installedAddons.push(duplicate.installedAddons[0]);assert.throws(()=>daemonViews({version:'2.17.0'},duplicate,rules),{code:'DIAGNOSTIC_ADDONS_AMBIGUOUS'});
 const bad=structuredClone(addons);bad.installedAddons[0].version='0.1.0';assert.throws(()=>daemonViews({version:'2.17.0'},bad,rules),{code:'DIAGNOSTIC_ADDONS_MISMATCH'});
});
test('expiration during probes stops further traffic and still tears down the shared namespace',async t=>{
 const d=await setup(t,'expire-probe'),r=await d.diagnostic.run();assert.equal(r.reason,'DIAGNOSTIC_EXPIRED');assert.equal(r.cleanup.cleaned,true);assert.notEqual(r.exitCode,0);assert.equal(d.calls.filter(a=>a.at(-1).startsWith('http')).length,1);
});
test('diagnostic resources cannot enter the production runtime registry even with mocked catalog readiness',async t=>{
 const d=await setup(t);const authorization={projectId:18,executionId:3,userId:7,targetId:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',fixtureKind:fixture.PYTHON_KIND,hostname:d.scope.scanId+'.test',ip:'172.30.26.2',port:18080,scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:config.imageId,expiresAt:Date.now()+60000,fixtureContainerId:'f'.repeat(64),scannerNetworkId:'1'.repeat(64)};
 t.mock.method(require('../services/activeRuntimeArtifacts'),'assertReady',()=>catalog);t.mock.method(require('../services/dockerAdapter'),'isRuntimeAdapter',()=>true);
 d.lifecycle.states.set(d.scope.scanId,'READY');d.lifecycle.resources.set(d.scope.scanId,{diagnosticOnly:true,fixtureResource:{id:authorization.fixtureContainerId,fixtureKind:fixture.PYTHON_KIND},owned:{networks:[{id:authorization.scannerNetworkId}]}});
 assert.throws(()=>require('../services/activeRuntimeRegistry').register(authorization,{lifecycle:d.lifecycle,adapter:d.adapter,scanId:d.scope.scanId}),{code:'ACTIVE_RUNTIME_BLOCKED'});
});
test('genuine saved daemon view shapes satisfy readiness without rewriting historical FAIL or proving containment',()=>{
 const evidence=require('./fixtures/zap-shared-namespace-runtime-readiness.json');
 const ready=require('../services/zapContainmentDiagnostic').daemonViews(evidence.version,evidence.addons,evidence.rules);
 assert.equal(ready.version,'2.17.0');assert.equal(evidence.historicalReportStatus,'FAIL');assert.ok(ready.ruleIds.includes('40018'));assert.equal(require('../config/active-runtime-artifacts.json').containmentAdapterValidated,false);
});
test('startup errors are captured before cleanup without replacing the original failure',async t=>{
 for(const scenario of ['workspace','addon','policy','preferences','binding','early-exit','missing-tmpfs','invalid-command','api-timeout','container-exit','malformed-startup']){
  await t.test(scenario,async t=>{
   const d=await setup(t,scenario),r=await d.diagnostic.run();
   assert.notEqual(r.status,'PASS');assert.equal(r.exitCode,1);assert.equal(r.cleanup.cleaned,true);
   assert.ok(r.startupEvidence,JSON.stringify({scenario,reason:r.reason,stage:r.stage,resources:r.resources}));assert.ok(r.startupEvidence.container);
   if(scenario==='early-exit'){assert.equal(r.reason,'DIAGNOSTIC_DAEMON_EXITED');assert.equal(r.startupEvidence.daemonExitCode,2);}
   if(scenario==='api-timeout'){assert.equal(r.reason,'DIAGNOSTIC_INITIALIZATION_TIMEOUT');assert.equal(r.startupEvidence.readinessCheck,'DIAGNOSTIC_API_NOT_READY');}
   if(['workspace','addon','policy','preferences','binding'].includes(scenario))assert.ok(r.startupEvidence.log.classification);
   const capture=d.calls.findIndex(a=>a.includes(require('../services/zapStartupEvidence').PROBE));
   const removal=d.calls.findIndex(a=>a[0]==='rm'&&a.at(-1)==='5'.repeat(64));
   if(scenario!=='container-exit')assert.ok(capture>=0&&removal>capture);
   else {assert.equal(r.startupEvidence.container.exitCode,137);assert.equal(r.startupEvidence.container.oomKilled,true);}
   assert.ok(!JSON.stringify(r).includes('/zap/wrk/session'));
  });
 }
});
test('startup excerpts redact credentials and host paths and remain bounded',()=>{
 const {summarize}=require('../services/zapStartupEvidence');
 const r=summarize('ERROR api.key=private-key token=secret /home/hammad/private-file Read-only file system\n'+'ERROR '.repeat(30000),['private-key']);
 assert.ok(r.truncated);assert.ok(r.excerpt.length<=8192);assert.ok(r.bytes>8192);assert.match(r.sha256,/^[a-f0-9]{64}$/);
 assert.ok(!r.excerpt.includes('private-key'));assert.ok(!r.excerpt.includes('token=secret'));assert.ok(!r.excerpt.includes('/home/hammad'));assert.ok(r.categories.includes('filesystem'));
});
test('genuine retained failed initialization proves mount configuration but not the underlying log cause',()=>{
 const saved=require('./fixtures/zap-containment-init-failure.json');
 assert.equal(saved.historicalReason,'DIAGNOSTIC_INITIALIZATION_FAILED');assert.equal(saved.startupLogRetained,false);
 assert.equal(saved.container.running,true);assert.equal(saved.container.exitCode,0);
 assert.deepEqual(saved.mounts,[{Type:'bind',Destination:'/zap/wrk',RW:false}]);
 assert.match(saved.tmpfs['/home/zap/.ZAP'],/size=256m,uid=1000,gid=1000,mode=0700/);
});
test('genuine harmless INFO excerpt reaches the complete mocked flow with independent positive readiness',async t=>{
 const d=await setup(t,'genuine-info'),r=await d.diagnostic.run();
 assert.equal(r.status,'PASS',JSON.stringify(r));assert.equal(r.verification,'MOCK_ONLY_NOT_VERIFIED');assert.equal(r.cleanup.cleaned,true);assert.equal(r.exitCode,0);
 assert.equal(r.initialization.writablePathsVerified,true);assert.equal(r.initialization.policy.xmlParsed,true);assert.equal(r.containmentReady,false);
});
test('missing positive policy/writable evidence and unsafe initialization listeners prevent probes',async t=>{
 for(const scenario of ['readonly-runtime','missing-policy','startup-listener'])await t.test(scenario,async t=>{
  const d=await setup(t,scenario),r=await d.diagnostic.run();assert.notEqual(r.status,'PASS');assert.equal(r.exitCode,1);assert.equal(r.cleanup.cleaned,true);
  assert.equal(d.state.helper,false);assert.ok(!d.calls.some(a=>a[0]==='run'&&a.includes(client.IMAGE)));
 });
});

test('opt-in commissioning response diagnostic sends exactly two authenticated fixed benign ZAP requests',async t=>{
 const d=await setup(t,'response-ok'),r=await d.diagnostic.run();
 try{assert.equal(r.status,'PASS',JSON.stringify(r));assert.equal(d.state.applicationRequests,2);assert.equal(r.commissioningResponse.zapOriginated,true);assert.equal(r.fullContainment,false);assert.equal(r.containmentReady,false);assert.equal(r.cleanup.cleaned,true);assert.equal(r.commissioningResponse.productionReady,false);
 const calls=d.calls.filter(a=>a[4]==='/zap/wrk/commissioning-probe.py');assert.equal(calls.length,2);for(const a of calls){assert.equal(a[5],'request');const input=JSON.parse(a.slice(6).join(''));assert(input.key);assert.match(input.request,new RegExp('^GET http://'+d.scope.scanId+'\\.test:18080/test/(sqli\\?id=1|xss\\?q=hello)&cs_commission=[a-f0-9]{32}-[01] HTTP/1.1'));}
 const stat=await fs.stat(r.responseEvidenceFile);assert.equal(stat.mode&0o777,0o600);assert.equal((await fs.stat(require('path').dirname(r.responseEvidenceFile))).mode&0o777,0o700);
 }finally{if(r.responseEvidenceFile)await fs.rm(require('path').dirname(r.responseEvidenceFile),{recursive:true,force:true});}
});
for(const scenario of ['response-redirect','response-malformed'])test('response diagnostic rejects '+scenario+' and persists evidence before cleanup',async t=>{
 const d=await setup(t,scenario),r=await d.diagnostic.run();try{assert.equal(r.status,'BLOCKED');assert.equal(r.reason,'COMMISSIONING_RESPONSE_BLOCKED');assert.equal(d.state.applicationRequests,1);assert.equal(r.cleanup.cleaned,true);assert(r.responseDiagnostic.failedPredicates.length);assert(r.responseEvidenceFile);assert.equal(d.state.zap,false);}finally{if(r.responseEvidenceFile)await fs.rm(require('path').dirname(r.responseEvidenceFile),{recursive:true,force:true});}
});
test('response diagnostic evidence write failure blocks and always cleans',async t=>{
 t.mock.method(require('../services/commissioningResponseEvidence'),'save',async()=>{throw Error('offline disk failure');});const d=await setup(t,'response-ok'),r=await d.diagnostic.run();assert.equal(r.status,'BLOCKED');assert.equal(r.reason,'DIAGNOSTIC_RESPONSE_EVIDENCE_WRITE_FAILED');assert.equal(r.cleanup.cleaned,true);assert.equal(d.state.applicationRequests,2);
});
test('response capability is opt-in, cannot call arbitrary actions or become a production authorization',async t=>{
 const d=await setup(t);await assert.rejects(d.diagnostic.api('core/action/sendRequest'),{code:'DIAGNOSTIC_ACTION_FORBIDDEN'});assert.equal(require('../services/module2ActiveDast').isBaselineAuthorization(d.diagnostic.scope),false);assert.throws(()=>validate({...d.scope,commissioningResponse:'true'}));const r=await d.diagnostic.run();assert.equal(r.status,'PASS');assert.equal(d.state.applicationRequests,undefined);assert.equal(r.commissioningResponse,undefined);
});


test('passive autorun is explicit, diagnostic-only, one command, strictly parsed and fully cleaned',async t=>{
 const d=await setup(t,'passive-ok'),r=await d.diagnostic.run();assert.equal(r.status,'PASS',JSON.stringify(r));assert.equal(r.passiveAutomation.completed,true);assert.equal(r.passiveAutomation.activeScanJobs,0);assert.equal(r.passiveAutomation.productionReady,false);assert.equal(r.fullContainment,false);assert.equal(r.containmentReady,false);assert.equal(d.state.applicationRequests,2);assert.equal(d.state.planRuns,1);assert.equal(r.cleanup.cleaned,true);assert.equal(d.state.zap,false);assert.equal(d.state.fixture,false);assert.equal(d.state.helper,false);
 const saved=JSON.parse(await fs.readFile(r.automationEvidenceFile,'utf8'));assert.equal(saved.diagnosticOnly,true);assert.equal(saved.stdout.classification,null);assert.equal(saved.exitCode,0);assert.equal((await fs.stat(require('path').dirname(r.automationEvidenceFile))).mode&511,448);assert.equal((await fs.stat(r.automationEvidenceFile)).mode&511,384);
 const dir=d.state.directory;await assert.rejects(fs.stat(dir),{code:'ENOENT'});assert.equal(process.env.DAST_ACTIVE_ENABLED,'false');
 await fs.rm(require('path').dirname(r.automationEvidenceFile),{recursive:true});await fs.rm(require('path').dirname(r.responseEvidenceFile),{recursive:true});
});
for(const scenario of ['passive-unknown','passive-error','passive-malformed','passive-bad-report','passive-escape','passive-no-addon'])test('passive diagnostic fails closed and cleans after '+scenario,async t=>{
 const d=await setup(t,scenario),r=await d.diagnostic.run();assert.notEqual(r.status,'PASS',JSON.stringify(r));assert.equal(r.cleanup.cleaned,true,JSON.stringify(r));assert.equal(r.fullContainment,false);assert.equal(d.state.planRuns||0,scenario==='passive-no-addon'?0:1);
 if(r.automationEvidenceFile)await fs.rm(require('path').dirname(r.automationEvidenceFile),{recursive:true});if(r.responseEvidenceFile)await fs.rm(require('path').dirname(r.responseEvidenceFile),{recursive:true});
});
test('passive evidence write failure prevents success and still performs cleanup',async t=>{
 const d=await setup(t,'passive-ok');t.mock.method(require('../services/zapAutomationEvidence'),'save',async()=>{throw Object.assign(Error('private storage'),{code:'ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED'});});
 const r=await d.diagnostic.run();assert.notEqual(r.status,'PASS');assert.equal(r.reason,'ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED');assert.equal(r.cleanup.cleaned,true);
 if(r.responseEvidenceFile)await fs.rm(require('path').dirname(r.responseEvidenceFile),{recursive:true});
});
test('passive plan rejects active jobs, spiders, arbitrary targets and forged execution capabilities',async()=>{
 const {passivePlan,assertPassivePlan,claimPassivePlanPermit,verifyPassivePlanPermit}=require('../services/zapContainmentDiagnostic'),origin='http://fixture.test:18080',plan=passivePlan(origin);
 assert.equal(assertPassivePlan(plan,origin),true);assert.doesNotMatch(plan,/type: (?:activeScan|spider)/);assert.match(plan,/type: passiveScan-wait/);
 for(const changed of [plan.replace('type: requestor','type: activeScan'),plan.replace('type: requestor','type: spider'),plan.replace('http://fixture.test','http://other.test'),plan.replace('id=1','id=2'),plan+'  - type: activeScan\n'])assert.throws(()=>assertPassivePlan(changed,origin),{code:'DIAGNOSTIC_PASSIVE_PLAN_BLOCKED'});
 for(const bad of ['http://external.com:18080','http://169.254.169.254:18080','http://fixture.test:18081','https://fixture.test:18080'])assert.throws(()=>passivePlan(bad));
 const input={scannerId:'a'.repeat(64),gatewayId:'b'.repeat(64),index:0,args:['-cmd','-autorun','/zap/wrk/plan-0.yaml']};
 assert.throws(()=>claimPassivePlanPermit({},input),{code:'DIAGNOSTIC_ACTION_FORBIDDEN'});assert.throws(()=>verifyPassivePlanPermit({},input),{code:'DIAGNOSTIC_ACTION_FORBIDDEN'});
 let calls=0;await assert.rejects(require('../services/zapCommissioningTraffic').executePlan({...input,diagnosticPermit:{},adapter:{run(){calls++;}},verify:async()=>{}}),{code:'DIAGNOSTIC_ACTION_FORBIDDEN'});assert.equal(calls,0);
});

test('Active diagnostic runs exactly one isolated plan, retains report and never promotes production',async t=>{
 const d=await setup(t,'active-ok'),r=await d.diagnostic.run();assert.equal(r.status,'PASS',JSON.stringify(r));assert.equal(r.activeAutomation.activeScanJobs,1);assert.equal(r.activeAutomation.rateEnforcement,'UNVERIFIED');assert.equal(r.activeAutomation.productionReady,false);assert.equal(d.state.planRuns,1);assert.equal(r.cleanup.cleaned,true);assert.ok(r.activeEvidence.file);const m=JSON.parse(await fs.readFile(r.activeEvidence.file));assert.ok(m.artifacts.report.storedSha256);assert.notEqual(m.acceptance,'PASS');assert.equal(r.fullContainment,false);
});
test('Active diagnostic defaults reject forged capability and preserve fixed policy',()=>{
 const mod=require('../services/zapContainmentDiagnostic'),old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';try{assert.throws(()=>mod.validate({scope:'zap-python-containment',scanId:'forged-active',projectId:11,executionId:32,expiresAt:Date.now()+10000,activeDiagnostic:true,activePermit:{}}),{code:'ACTIVE_DIAGNOSTIC_AUTHORIZATION_REQUIRED'});const p=mod.activeDiagnosticPlan('http://fixture.test:18080');assert.equal((p.match(/type: activeScan\n/g)||[]).length,1);assert.doesNotMatch(p,/type: spider/);for(const id of [40012,40014,40016,40017,40018,40019,40020])assert.ok(p.includes('id: '+id));assert.match(p,/threadPerHost: 1/);assert.match(p,/delayInMs: 500/);assert.match(p,/maxScanDurationInMins: 1/);}finally{if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
for(const code of ['DIAGNOSTIC_STARTUP_TIMEOUT','DIAGNOSTIC_ACTIVE_TIMEOUT','DIAGNOSTIC_REPORT_TIMEOUT','DIAGNOSTIC_OVERALL_TIMEOUT'])test(`Active ${code} preserves failure and cleans owned resources`,async t=>{
 const {diagnostic}=await setup(t,'active-ok');
 t.mock.method(require('../services/zapDiagnosticBudget'),'create',()=>{throw Object.assign(Error('deadline'),{code});});
 const result=await diagnostic.run();assert.equal(result.reason,code);assert.equal(result.status,'BLOCKED');assert.equal(result.exitCode,1);assert.equal(result.cleanup.cleaned,true);
});
