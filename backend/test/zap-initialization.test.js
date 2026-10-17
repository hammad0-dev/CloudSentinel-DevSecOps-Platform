'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {STORAGE,diagnosticStorageArguments,profileBootstrapArguments,jvmBootstrapArguments,jvmProperties,assertInitialized,startupFailure,assertListeners}=require('../services/zapInitialization');
const writable=require('../config/zap-writable-paths.json');
const evidence=require('./helpers/zapInitializationEvidence');
const errors=require('./fixtures/zap-storage-initialization-errors.json');
const imageId='sha256:'+'a'.repeat(64);

test('diagnostic storage keeps networking disabled and writable mounts bounded and owned',()=>{
  const args=diagnosticStorageArguments();
  assert.equal(args[args.indexOf('--network')+1],'none');
  assert.equal(args[args.indexOf('--user')+1],'1000:1000');
  assert.equal(args[args.indexOf('--memory')+1],'1536m');
  assert.ok(args.includes('--read-only'));
  assert.equal(args.filter(arg=>arg==='--tmpfs').length,4);
  const mounts=args.filter(arg=>arg.startsWith('/'));
  assert.ok(mounts.some(arg=>arg.includes('/home/zap/.ZAP:')&&arg.includes('size=256m')&&arg.includes('mode=0700')));
  assert.ok(mounts.every(arg=>['uid=1000','gid=1000','noexec','nosuid','nodev','size='].every(option=>arg.includes(option))));
  assert.ok(!args.includes('--mount')&&!args.includes('--volume')&&!args.includes('--publish'));
  assert.ok(mounts.includes(`${writable.profilePath}:rw,noexec,nosuid,nodev,size=4m,uid=1000,gid=1000,mode=0700`));
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

test('profile and preferences readiness requires measured owned writable paths and preserved seed',()=>{
  for(const change of [s=>{delete s.profile;},s=>{s.profile.uid=0;},s=>{s.profile.capacityBytes=32*1024*1024;},s=>{s.profile.seedSha256='wrong';},s=>{s.profile.writable=false;}]){
    const value=evidence();change(value.storage);assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_PROFILE_NOT_READY'});
  }
  for(const change of [s=>{delete s.javaPreferences;},s=>{s.javaPreferences.rootProperty='/home/zap';},s=>{s.javaPreferences.uid=0;},s=>{s.javaPreferences.writable=false;}]){
    const value=evidence();change(value.storage);assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_PREFERENCES_NOT_READY'});
  }
});

test('genuine Firefox profile and Java preferences errors cannot establish readiness',()=>{
  const failures=[[errors.profileFailure,'ZAP_PROFILE_NOT_READY'],[errors.preferencesWarning,'ZAP_PREFERENCES_NOT_READY']];
  for(const [line,code] of failures){const value=evidence();value.startupLog+='\n'+line;assert.throws(()=>assertInitialized(value,imageId),{code});}
  assert.equal(jvmProperties(),'-Xmx512m -Djava.util.prefs.userRoot=/home/zap/.ZAP\n');
  assert.equal(Buffer.from(jvmBootstrapArguments().at(-2),'base64').toString(),jvmProperties());
});

test('dual-stack listener evidence accepts IPv4, IPv6 and normalized mapped loopback only',()=>{
  for(const entry of [{family:'IPv4',address:'127.0.0.1',port:8090,nativeAddress:'0100007F'},
    {family:'IPv6',address:'::1',port:8090,nativeAddress:'00000000000000000000000001000000'},
    {family:'IPv6',address:'127.0.0.1',port:8090,nativeAddress:'0000000000000000FFFF00000100007F'}]){
    assert.equal(assertListeners({complete:true,tcpComplete:true,tcp6Complete:true,listeners:[entry]}),true);
  }
  for(const address of ['0.0.0.0','::','192.0.2.1','::ffff:0:0']){
    const value=evidence();value.listeners.listeners.push({family:'IPv6',address,port:40247});
    assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_NON_LOOPBACK_LISTENER'});
  }
  const value=evidence();value.listeners.tcp6Complete=false;
  assert.throws(()=>assertInitialized(value,imageId),{code:'ZAP_LISTENERS_UNVERIFIED'});
  const contradictory=evidence();contradictory.listeners.listeners[0].nativeAddress='0'.repeat(32);
  assert.throws(()=>assertInitialized(contradictory,imageId),{code:'ZAP_LISTENERS_UNVERIFIED'});
});

test('seed bootstrap uses audited bytes and complies with strict Docker argument limits',()=>{
  const crypto=require('node:crypto');
  const args=profileBootstrapArguments();
  assert.equal(crypto.createHash('sha256').update(Buffer.from(writable.profileSeed.base64,'base64')).digest('hex'),writable.profileSeed.sha256);
  assert.equal(Buffer.from(writable.profileSeed.base64,'base64').length,101);
  assert.ok(args.includes('-I'));
  assert.doesNotThrow(()=>require('../services/dockerAdapter').operation(['exec','f'.repeat(64),...args]));
  assert.doesNotThrow(()=>require('../services/dockerAdapter').operation(['exec','f'.repeat(64),...jvmBootstrapArguments()]));
});
