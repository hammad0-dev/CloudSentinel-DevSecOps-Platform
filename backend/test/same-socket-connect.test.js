"use strict";
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('fs/promises'),os=require('os'),path=require('path'),{spawnSync}=require('child_process');
const {mockDocker}=require('./helpers/runtimeDocker');
const client=require('../services/dastAcceptanceClient');
const {observeSameSocketConnect,EXECUTABLE}=require('../services/sameSocketConnect');
const valid={schemaVersion:1,peerIp:'172.30.25.3',peerPort:3128,requestedAuthority:'fixture.test:8080',responseStatus:403,connected:true,squidServer:true,accessDenied:true,headersValid:true,complete:true,error:null};
async function setup(t) {
  const artifacts=require("../services/nativeConnectArtifact");
  const artifact=await artifacts.stage("s1");t.after(()=>artifacts.cleanup(artifact));
  const d=mockDocker(),c=await client.provision(d.adapter,{scanId:'s1',networkId:d.ids.scanner,networkReference:d.refs[0],nativeArtifact:artifact});
  return {...d,c,options:{gatewayId:d.ids.gateway,networkReferences:d.refs,target:{hostname:'fixture.test',port:8080}}};
}
test('experimental same-socket result must match independently inspected gateway and authority',async(t)=>{
  const d=await setup(t);d.state.probe=(a,cb)=>cb(null,JSON.stringify(valid),'');
  const result=await observeSameSocketConnect(d.adapter,d.c,d.options);
  assert.equal(result.actual,'DENY');assert.equal(result.complete,true);
  assert.equal(result.fullContainment,false);assert.equal(result.verification,'EXPERIMENTAL_NOT_ACCEPTANCE');
  assert.equal(require('../services/runtimeObservation').runtimeReady(result),false);
  assert.deepEqual(d.calls.find(a=>a[2]===EXECUTABLE),['exec',d.ids.client,EXECUTABLE,'172.30.25.3','3128','fixture.test:8080']);
});
test('wrong or missing peer, headers, authority, timeout and contradictory output fail closed',async(t)=>{
  const d=await setup(t);
  for(const change of [{peerIp:''},{peerIp:'10.0.0.1'},{peerPort:3129},{requestedAuthority:'other.test:8080'},{squidServer:false},{accessDenied:false},{headersValid:false},{error:'TIMEOUT',complete:false},{connected:false},{schemaVersion:2},{responseStatus:407},{responseStatus:200}]) {
    d.state.probe=(a,cb)=>cb(null,JSON.stringify({...valid,...change}),'');
    const result=await observeSameSocketConnect(d.adapter,d.c,d.options);assert.equal(result.actual,'INCONCLUSIVE');assert.equal(result.complete,false);
  }
  for(const stdout of ['', 'null', '[]', 'not json', 'x'.repeat(4097)]) {
    d.state.probe=(a,cb)=>cb(null,stdout,'');assert.equal((await observeSameSocketConnect(d.adapter,d.c,d.options)).actual,'INCONCLUSIVE');
  }
  d.state.probe=(a,cb)=>cb(Object.assign(new Error('timeout'),{code:1}),JSON.stringify({...valid,error:'TIMEOUT',complete:false}),'');
  assert.equal((await observeSameSocketConnect(d.adapter,d.c,d.options)).actual,'INCONCLUSIVE');
  d.state.probe=(a,cb)=>cb(null,JSON.stringify(valid),'contradictory warning');
  assert.equal((await observeSameSocketConnect(d.adapter,d.c,d.options)).actual,'INCONCLUSIVE');
  d.state.probe=(a,cb)=>cb(Object.assign(new Error('contradictory tunnel'),{code:1}),JSON.stringify({...valid,responseStatus:200,complete:false,error:'UNEXPECTED_TUNNEL'}),'');
  assert.equal((await observeSameSocketConnect(d.adapter,d.c,d.options)).actual,'INCONCLUSIVE');
  d.state.probe=(a,cb)=>cb(Object.assign(new Error('tunnel unexpectedly established'),{code:1}),JSON.stringify({...valid,responseStatus:200,accessDenied:false,complete:false,error:'UNEXPECTED_TUNNEL'}),'');
  assert.equal((await observeSameSocketConnect(d.adapter,d.c,d.options)).actual,'ALLOW');
});
test('ownership mismatch prevents experimental executable invocation',async(t)=>{
  const d=await setup(t);d.state.foreign=true;
  await assert.rejects(observeSameSocketConnect(d.adapter,d.c,d.options));
  assert.ok(!d.calls.some(a=>a[2]===EXECUTABLE));
});
test('caller retains lifecycle cleanup on experimental verification failure',async(t)=>{
  const {runAcceptance}=require('../scripts/dast-acceptance');const d=await setup(t);let cleaned=false;
  d.state.probe=(a,cb)=>cb(null,JSON.stringify({...valid,peerPort:1}),'');
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {await assert.rejects(runAcceptance({projectId:'p',executionId:'e',scanId:'s1',target:{hostname:'fixture.test',port:8080}},{async provision(){const r=await observeSameSocketConnect(d.adapter,d.c,d.options);if(!r.complete)throw Object.assign(new Error('inconclusive'),{code:'PROBE_INCONCLUSIVE'});return r;},async cleanup(){const r=await client.cleanup(d.adapter,d.c);cleaned=r.cleaned;return r;}}),{code:'PROBE_INCONCLUSIVE'});assert.equal(cleaned,true);}
  finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
const compiler=['cc','gcc','clang'].find(bin=>spawnSync(bin,['--version'],{encoding:'utf8',timeout:5000}).status===0);
test('C client syscall unit tests (no real socket calls)',{skip:compiler?false:'No installed C compiler: native source has NOT been compiled or validated'},async(t)=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'cs-connect-native-unit-'));
  try {
    const exe=path.join(dir,'unit');
    const built=spawnSync(compiler,['-std=c11','-O2','-Wall','-Wextra','-Werror',path.join(__dirname,'../native/connect-peer-test.c'),'-o',exe],{encoding:'utf8',timeout:30000});assert.equal(built.status,0,built.stderr);
    const ran=spawnSync(exe,[],{encoding:'utf8',timeout:10000});assert.equal(ran.status,0,ran.stderr);
  } finally {await fs.rm(dir,{recursive:true,force:true});}
});
