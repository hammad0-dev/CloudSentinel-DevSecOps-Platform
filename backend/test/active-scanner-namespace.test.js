'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {mockDocker}=require('./helpers/runtimeDocker'),client=require('../services/dastAcceptanceClient'),binding=require('../services/activeScannerBinding');
async function setup(t,scenario='ok'){
 const saved={flag:process.env.DAST_ACTIVE_ENABLED,node:process.env.NODE_ENV};process.env.DAST_ACTIVE_ENABLED='true';process.env.NODE_ENV='test';t.after(()=>{for(const [key,value] of [['DAST_ACTIVE_ENABLED',saved.flag],['NODE_ENV',saved.node]])if(value===undefined)delete process.env[key];else process.env[key]=value;});
 const d=mockDocker(),parent='5'.repeat(64),image='sha256:'+'a'.repeat(64),directory='/tmp/cs-active-namespace-unit',w=require('../config/zap-writable-paths.json'),init=require('../services/zapInitialization');
 t.mock.method(require('../services/dockerAdapter'),'isRuntimeAdapter',v=>v===d.adapter);t.mock.method(require('../services/nativeConnectArtifact'),'verify',async a=>a);
 const original=d.adapter.executor;
 d.adapter.executor=(bin,args,options,cb)=>{
  if(args[0]==='inspect'&&args.at(-1)===parent){const raw={Id:parent,Name:'/cs-zap-s1',Image:image,Config:{User:'1000:1000',Image:image,Labels:{'cloudsentinel.owner':'cloudsentinel-s1','cloudsentinel.scan':'s1','cloudsentinel.role':scenario==='wrong-role'?'zap-containment-diagnostic':'active-zap'}},State:{Running:true},HostConfig:{NetworkMode:d.ids.scanner,ReadonlyRootfs:true,Privileged:false,CapAdd:[],CapDrop:['ALL'],SecurityOpt:['no-new-privileges:true'],Memory:1536*1048576,NanoCpus:1000000000,PidsLimit:128,Sysctls:{'net.ipv6.conf.all.disable_ipv6':'1','net.ipv6.conf.default.disable_ipv6':'1'},Tmpfs:{'/tmp':'rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=1777','/home/zap/.ZAP':init.homeTmpfs().split(':')[1],[w.profilePath]:init.profileTmpfs().split(':')[1]}},Mounts:[{Type:'bind',Source:directory,Destination:'/zap/wrk',RW:false}],NetworkSettings:{Networks:d.state.clientNetworks,Ports:{}}};
   if(scenario==='wrong-image')raw.Image='sha256:'+'b'.repeat(64);if(scenario==='wrong-mount')raw.Mounts[0].Source='/tmp/foreign';if(scenario==='extra-interface')raw.NetworkSettings.Networks={...raw.NetworkSettings.Networks,extra:{NetworkID:'f'.repeat(64)}};if(scenario==='limits')raw.HostConfig.Memory=0;
   return cb(null,JSON.stringify(raw),'');
  }
  if(args[0]==='inspect'&&args.at(-1)===d.ids.client)return original(bin,args,options,(e,stdout,stderr)=>{const raw=JSON.parse(stdout);raw.HostConfig.NetworkMode='container:'+parent;raw.HostConfig.Memory=134217728;raw.HostConfig.NanoCpus=500000000;raw.HostConfig.PidsLimit=64;raw.NetworkSettings.Networks={};cb(e,JSON.stringify(raw),stderr);});
  if(args[0]==='exec'&&args[1]===d.ids.client&&args[2]==='cat'&&args[3].startsWith('/proc/net/'))return cb(null,'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'+(d.state.unsafeListener&&args[3]==='/proc/net/tcp'?'0: 00000000:1F9A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1\n':''),'');
  if(args[0]==='exec'&&args[1]===parent&&args.includes('python3'))return cb(null,scenario==='inode'?'net:[777]\n':'net:[123]\n','');
  if(args[0]==='exec'&&args[1]===d.ids.client&&args[2]==='readlink')return cb(null,'net:[123]\n','');
  return original(bin,args,options,cb);
 };
 const context={projectId:42,executionId:100,userId:7},authorization=require('../services/module2ActiveDast').issueAuthorization({...context,scannerNetworkId:d.ids.scanner,fixtureContainerId:'f'.repeat(64),fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.26.2',port:18080,scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:image,expiresAt:Date.now()+60000},context);
 const token=binding.permit(d.adapter,authorization,'s1',parent,image,directory);
 const artifact={scanId:'s1',filePath:'/tmp/native-unit',mount:'type=bind,src=/tmp/native-unit,dst=/opt/cloudsentinel/connect-peer,readonly'};
 return {...d,parent,token,options:{scanId:'s1',networkId:d.ids.scanner,networkReference:d.refs[0],nativeArtifact:artifact,namespaceParent:parent,namespaceScope:token}};
}
test('production helper independently inspects active ZAP identity, sandbox and matching live namespace',async t=>{
 const d=await setup(t),helper=await client.provision(d.adapter,d.options),n=await client.verifyClient(d.adapter,helper);
 const fresh=await binding.verify(d.adapter,{token:d.token,helper,reference:d.refs[0]},d.parent);assert.equal(fresh.routes.ipv6.length,0);
 assert.equal(n.namespaceEvidence.zapContainerId,d.parent);assert.equal(n.namespaceEvidence.namespaceId,'net:[123]');assert.equal(n.namespaceEvidence.zapApplicationRequests,false);
 const run=d.calls.find(a=>a[0]==='run');assert.ok(run.includes('cloudsentinel.scan=s1'));assert.equal(run[run.indexOf('--network')+1],'container:'+d.parent);
 binding.revoke(d.token);await assert.rejects(client.verifyClient(d.adapter,helper),{code:'NAMESPACE_UNVERIFIED'});assert.equal((await client.cleanup(d.adapter,helper)).cleaned,true);
});
test('production binding rejects changed image, foreign mount, wrong role, limits, interfaces and namespace',async t=>{
 for(const scenario of ['wrong-image','wrong-mount','wrong-role','limits','extra-interface','inode'])await t.test(scenario,async t=>{const d=await setup(t,scenario);try{await assert.rejects(client.provision(d.adapter,d.options));}finally{binding.revoke(d.token);assert.equal((await client.cleanup(d.adapter,{id:d.ids.client,owner:'cloudsentinel-s1'})).cleaned,true);}});
});
test('fresh production verification rejects a route introduced after initial binding',async t=>{
 const d=await setup(t),helper=await client.provision(d.adapter,d.options),record={token:d.token,helper,reference:d.refs[0]};
 try{await binding.verify(d.adapter,record,d.parent);d.state.route='default via 172.30.25.1 dev eth0\n';await assert.rejects(binding.verify(d.adapter,record,d.parent));}
 finally{binding.revoke(d.token);assert.equal((await client.cleanup(d.adapter,helper)).cleaned,true);}
});
test('production listener re-observation rejects a newly exposed non-loopback socket',async t=>{
 const d=await setup(t),helper=await client.provision(d.adapter,d.options),record={token:d.token,helper,reference:d.refs[0]};
 try{await binding.verify(d.adapter,record,d.parent);d.state.unsafeListener=true;await assert.rejects(binding.verify(d.adapter,record,d.parent),{code:'NON_LOOPBACK_LISTENER'});}
 finally{binding.revoke(d.token);assert.equal((await client.cleanup(d.adapter,helper)).cleaned,true);}
});
