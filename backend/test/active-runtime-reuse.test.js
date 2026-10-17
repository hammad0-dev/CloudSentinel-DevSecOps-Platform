'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
function setup(t){
 const registry=require('../services/activeRuntimeRegistry'),{ActiveZapRuntime}=require('../services/activeZapRuntime'),{SecureGatewayLifecycle}=require('../services/dastGateway');
 const adapter={},lifecycle=Object.create(SecureGatewayLifecycle.prototype),runtime=Object.create(ActiveZapRuntime.prototype);
 const scanId='warm-unit',authorization={projectId:11,executionId:200,userId:3,targetId:'target-unit',expiresAt:Date.now()+180000,fixtureContainerId:'f'.repeat(64),scannerNetworkId:'1'.repeat(64),retainedScannerId:'5'.repeat(64)};
 lifecycle.adapter=adapter;lifecycle.states=new Map([[scanId,'READY']]);lifecycle.resources=new Map([[scanId,{fixtureResource:{id:authorization.fixtureContainerId,fixtureKind:'cloudsentinel-vulnerable-v1'},owned:{networks:[{id:authorization.scannerNetworkId}]}}]]);
 Object.assign(runtime,{adapter,lifecycle,scanId});let cleaned=0,verified=0,timer;
 runtime.retainedIdentity=()=>({scannerId:authorization.retainedScannerId});runtime.verifyRetained=async()=>{verified++;return {verified:true};};runtime.cleanup=async()=>{cleaned++;return {cleaned:true,residual:[]};};
 t.mock.method(require('../services/dockerAdapter'),'isRuntimeAdapter',()=>true);t.mock.method(require('../services/module2ActiveDast'),'validateAuthorization',()=>{});t.mock.method(require('../services/activeDastCommissioning'),'assertAuthorizationReady',()=>{});
 t.mock.method(global,'setTimeout',fn=>{timer=fn;return {unref(){}};});t.mock.method(global,'clearTimeout',()=>{});
 registry.register(authorization,{adapter,lifecycle,scanId,runtime});
 return {registry,authorization,runtime,async expire(){timer();await new Promise(resolve=>setImmediate(resolve));},counts:()=>({cleaned,verified})};
}
test('registry hands over the original private runtime once and rejects substituted scanner identity',async t=>{
 const d=setup(t);await d.registry.verifyPending(d.authorization);assert.equal(d.counts().verified,1);
 assert.throws(()=>d.registry.consume({...d.authorization,retainedScannerId:'9'.repeat(64)}));
 assert.equal(d.registry.consume(d.authorization),d.runtime);assert.throws(()=>d.registry.consume(d.authorization));assert.equal(d.counts().cleaned,0);
 await d.runtime.cleanup();assert.equal(d.counts().cleaned,1);
});
test('expiry cleans retained scanner/home through runtime, invalidates registry and invokes expiry listener',async t=>{
 const d=setup(t);let notified;t.mock.method(d.runtime,'cleanup',async()=>({cleaned:true,residual:[]}));
 d.registry.watchCleanup(d.authorization,d.authorization.targetId,async(result,expired)=>{notified={result,expired};});
 await d.expire();assert.equal(notified.expired,true);assert.equal(notified.result.cleaned,true);
 assert.throws(()=>d.registry.pendingFor(d.authorization,d.authorization.targetId));await assert.rejects(d.registry.verifyPending(d.authorization));
});
test('explicit cancellation cleans retained scanner rather than only fixture networks',async t=>{
 const d=setup(t);const r=await d.registry.cancelPending(d.authorization);assert.equal(r.cleaned,true);assert.equal(d.counts().cleaned,1);assert.throws(()=>d.registry.consume(d.authorization));
});
test('stale retained verification blocks and cleanup failure remains residual',async t=>{
 const d=setup(t);t.mock.method(d.runtime,'verifyRetained',async()=>{throw Error('stale');});await assert.rejects(d.registry.verifyPending(d.authorization));
 t.mock.method(d.runtime,'cleanup',async()=>({cleaned:false,residual:[{type:'scanner'}]}));
 const r=await d.registry.cancelPending(d.authorization);assert.equal(r.cleaned,false);assert.ok(r.residual.length);
});
