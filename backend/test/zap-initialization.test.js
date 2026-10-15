'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {STORAGE,diagnosticStorageArguments,assertInitialized,startupFailure}=require('../services/zapInitialization');
const evidence=require('./helpers/zapInitializationEvidence');
const errors=require('./fixtures/zap-storage-initialization-errors.json');
const imageId='sha256:'+'a'.repeat(64);

test('diagnostic storage keeps networking disabled and writable mounts bounded and owned',()=>{
  const args=diagnosticStorageArguments();
  assert.equal(args[args.indexOf('--network')+1],'none');
  assert.equal(args[args.indexOf('--user')+1],'1000:1000');
  assert.equal(args[args.indexOf('--memory')+1],'1536m');
  assert.ok(args.includes('--read-only'));
  assert.equal(args.filter(arg=>arg==='--tmpfs').length,3);
  const mounts=args.filter(arg=>arg.startsWith('/'));
  assert.ok(mounts.some(arg=>arg.includes('/home/zap/.ZAP:')&&arg.includes('size=256m')&&arg.includes('mode=0700')));
  assert.ok(mounts.every(arg=>['uid=1000','gid=1000','noexec','nosuid','nodev','size='].every(option=>arg.includes(option))));
  assert.ok(!args.includes('--mount')&&!args.includes('--volume')&&!args.includes('--publish'));
});

test('initialization requires bounded storage, owner, permissions, heap and native memory headroom',()=>{
  assert.equal(assertInitialized(evidence(),imageId),true);
  for(const change of [s=>{s.homeCapacityBytes=32*1024*1024;},s=>{s.uid=0;},s=>{s.gid=0;},s=>{s.mode='0777';},
    s=>{s.homeWritable=false;},s=>{s.readOnlyRootfs=false;},s=>{s.memoryLimitBytes=1024*1024*1024;},
    s=>{s.javaMaxHeapBytes=1024*1024*1024;},s=>{s.totalTmpfsLimitBytes=1024*1024*1024;},s=>{s.totalTmpfsLimitBytes=1;},s=>{s.homeAvailableBytes=0;}]){
    const value=evidence();change(value.storage);assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_STORAGE_NOT_READY'});
  }
  assert.equal(STORAGE.homeMiB,256);
});

test('genuine storage and policy errors block readiness regardless of successful version response',()=>{
  assert.equal(startupFailure(errors.installationFailure),'ZAP_STORAGE_EXHAUSTED');
  assert.equal(startupFailure('',errors.policyFailure),'ZAP_INITIALIZATION_CORRUPT');
  for(const [text,code] of [[errors.installationFailure,'ZAP_STORAGE_EXHAUSTED'],[errors.policyFailure,'ZAP_INITIALIZATION_CORRUPT']]){
    const value=evidence();value.startupLog+='\n'+text;
    assert.throws(()=>assertInitialized(value,imageId),{code});
  }
  assert.throws(()=>assertInitialized({version:'2.17.0'},imageId),{code:'ZAP_INITIALIZATION_INCOMPLETE'});
});

test('incomplete, truncated, failed or wrong-image initialization stays blocked',()=>{
  for(const change of [e=>{e.complete=false;},e=>{e.extensionsLoaded=false;},e=>{e.logsComplete=false;},e=>{e.logsTruncated=true;},
    e=>{e.observationExitCode=1;},e=>{e.startupLog='';},e=>{e.startupLog='version 2.17.0';},e=>{e.imageId='wrong';}]){
    const value=evidence();change(value);assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_INITIALIZATION_INCOMPLETE'});
  }
});

test('missing, empty or malformed policy evidence blocks readiness',()=>{
  for(const change of [e=>{e.policy=null;},e=>{e.policy.xmlParsed=false;},e=>{e.policy.apiLoaded=false;},e=>{e.policy.complete=false;},
    e=>{e.policy.bytes=0;},e=>{e.policy.sha256='unknown';}]){
    const value=evidence();change(value);assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_POLICY_NOT_INITIALIZED'});
  }
});

test('all seven installed and loaded add-ons must match the verified selection without duplicates',()=>{
  for(const name of ['ascanrules','automation','network','reports','commonlib','oast','database']){
    const missing=evidence();missing.installedAddons=missing.installedAddons.filter(a=>a.id!==name);
    assert.throws(()=>assertInitialized(missing,imageId),{code:'ZAP_ADDONS_NOT_INITIALIZED'});
    const unloaded=evidence();unloaded.loadedAddonIds=unloaded.loadedAddonIds.filter(id=>id!==name);
    assert.throws(()=>assertInitialized(unloaded,imageId),{code:'ZAP_ADDONS_NOT_INITIALIZED'});
  }
  for(const change of [e=>{e.installedAddons[0].version='999';},e=>{e.installedAddons[0].installationStatus='FAILED';},
    e=>{e.installedAddons.push({...e.installedAddons[0]});}]){
    const value=evidence();change(value);assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_ADDONS_NOT_INITIALIZED'});
  }
  const value=evidence();value.installedAddons.find(a=>a.id==='ascanrules').version='83.0.0';
  assert.equal(assertInitialized(value,imageId),true);
});

test('each required SQLi/XSS rule must occur in genuine scanner inventory',()=>{
  for(const id of evidence().activeRuleIds){
    const value=evidence();value.activeRuleIds=value.activeRuleIds.filter(rule=>rule!==id);
    assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_REQUIRED_RULES_MISSING'});
  }
  const value=evidence();value.activeRuleIds=['90026','90029'];
  assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_REQUIRED_RULES_MISSING'});
});

test('production Active DAST catalog remains blocked after offline storage correction',()=>{
  const {assertReady,artifacts}=require('../services/activeRuntimeArtifacts');
  assert.equal(artifacts.zap.capabilities,null);
  assert.throws(()=>assertReady(),{code:'ACTIVE_RUNTIME_BLOCKED'});
});
