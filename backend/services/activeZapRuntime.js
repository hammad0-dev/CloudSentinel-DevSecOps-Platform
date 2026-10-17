'use strict';
// Production scanner control for an existing, grant-bound live lifecycle.
// Historical acceptance JSON or caller-provided container snapshots are never used.
const fs=require('fs/promises'),path=require('path'),os=require('os'),crypto=require('crypto');
const {isIP}=require('net');
const {isRuntimeAdapter}=require('./dockerAdapter');
const {inspectOwnedNetwork,verifyMemberships}=require('./ownedDockerNetworks');
const {POLICY}=require('./dastActiveScanner');
const {STORAGE,homeTmpfs,profileTmpfs,profileBootstrapArguments,jvmBootstrapArguments,assertInitialized,startupFailure}=require('./zapInitialization');
const writable=require('../config/zap-writable-paths.json');
const {performance}=require('perf_hooks');
const verifiedReads=require('./verifiedReads');
const sessions=new WeakMap();
// Kept only in this process; neither a database snapshot nor an API field can
// manufacture a retained scanner. Restarting the backend invalidates reuse.
const retained=new WeakMap();
const fail=code=>Object.assign(new Error(code),{code,nonRetryable:true});
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function capabilities(catalog,{commissioning=false}={}) {
  if(commissioning&&!catalog?.zap?.capabilities)return require('./activeDastCommissioning').assertReady(catalog);
  const z=catalog?.zap,f=catalog?.fixture,c=z?.capabilities;
  for(const item of [z,f]) {
    const localFixture=item===f && /^sha256:[a-f0-9]{64}$/.test(item?.reference||'');
    const localZap=item===z&&item?.reference===require('../config/zap-containment-diagnostic.json').imageId;
    if(!item || !(localFixture || localZap || /^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$/.test(item.reference||'')) || item.imageId!==((localFixture||localZap)?item.reference:item.reference.split('@')[1]) || item.architecture!=='amd64' || item.os!=='linux')throw fail('ACTIVE_RUNTIME_BLOCKED');
    if(localFixture && (item.imageId!==require('./dastFixture').pythonArtifact().imageId || item.sourceSha256!==require('./dastFixture').pythonArtifact().sourceSha256))throw fail('ACTIVE_IMAGE_MISMATCH');
  }
  if(!c || c.imageId!==z.imageId || c.verified!==true || JSON.stringify([...(c.activeRuleIds||[])].sort())!==JSON.stringify([...POLICY.approvedPluginIds].sort()) || !['automation','spider','activeScan','report','proxy','rateLimit','sha256sum','python3'].every(k=>c.commands?.includes(k)) || c.commands?.includes('ip') || c.commands?.includes('nc') || f.fixtureKind!=='cloudsentinel-vulnerable-v1')throw fail('ACTIVE_POLICY_CAPABILITIES_BLOCKED');
  const contract=c.runtimeContract;
  const dependent=require('./activeDastCommissioning').UNKNOWN;
  if(!contract||dependent.some(k=>commissioning?![undefined,null,'UNKNOWN',true].includes(contract[k]):contract[k]!==true))throw fail('ACTIVE_POLICY_CAPABILITIES_BLOCKED');
  if(!contract || contract.apiBinding!=='LOOPBACK_ONLY' || contract.apiAuthentication!=='REQUIRED' || contract.maxRequestsPerSecond!==2 || contract.maxConcurrency!==1 || contract.spiderRateLimited!==true || contract.exactPathScope!==true || contract.exportFormat!=='traditional-json' || !/^[a-f0-9]{64}$/.test(contract.evidenceSha256||''))throw fail('ACTIVE_POLICY_CAPABILITIES_BLOCKED');
  assertInitialized(c.initialization,z.imageId);
  return catalog;
}
function proxyPolicy(target) {
  if(!/^[a-z0-9-]+\.test$/.test(target.hostname||'') || isIP(target.ip)!==4 || !/^172\.30\./.test(target.ip) || target.port!==18080)throw fail('ACTIVE_SCOPE_BLOCKED');
  return require('./squidPolicy').activePolicy(target);
}
function runArguments({scanId,networkId,image,directory,proxy,hostname,ip}) {
  if(!/^[a-z0-9_.-]{1,40}$/.test(scanId)||!/^[a-f0-9]{64}$/.test(networkId)||!/^http:\/\/172\.30\.\d+\.\d+:3128$/.test(proxy)||!/^[a-z0-9-]+\.test$/.test(hostname)||isIP(ip)!==4||/[,\r\n]/.test(directory))throw fail('ACTIVE_ARGUMENTS_BLOCKED');
  const containerName=`cs-zap-${scanId}`;
  return ['run','-d','--pull=never','--name',containerName,'--hostname',containerName,'--network',networkId,'--label',`cloudsentinel.owner=cloudsentinel-${scanId}`,'--label',`cloudsentinel.scan=${scanId}`,'--label','cloudsentinel.role=active-zap','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','128','--memory',`${STORAGE.memoryMiB}m`,'--cpus','1','--sysctl','net.ipv6.conf.all.disable_ipv6=1','--sysctl','net.ipv6.conf.default.disable_ipv6=1','--user','1000:1000','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=1777','--tmpfs',homeTmpfs(),'--tmpfs',profileTmpfs(),'--add-host',`${containerName}:127.0.0.1`,'--add-host',`${hostname}:${ip}`,'--mount',`type=bind,src=${directory},dst=/zap/wrk,readonly`,'--entrypoint','/bin/sh',image,'-c','sleep 900'];
}
function assertScannerSecurity(raw,{networkId,directory}){
  const h=raw.HostConfig||{},expected={'/tmp':'rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=1777','/home/zap/.ZAP':homeTmpfs().split(':')[1],[writable.profilePath]:profileTmpfs().split(':')[1]};
  if(raw.Config?.User!=='1000:1000'||h.NetworkMode!==networkId||h.ReadonlyRootfs!==true||h.Privileged||h.CapAdd?.length||!h.CapDrop?.includes('ALL')||!h.SecurityOpt?.includes('no-new-privileges:true')||h.Memory!==1536*1048576||h.NanoCpus!==1000000000||h.PidsLimit!==128||h.PublishAllPorts||Object.keys(h.PortBindings||{}).length||Object.values(raw.NetworkSettings?.Ports||{}).some(Boolean)||h.Binds?.length||!require('util').isDeepStrictEqual(h.Tmpfs,expected)||h.Sysctls?.['net.ipv6.conf.all.disable_ipv6']!=='1'||h.Sysctls?.['net.ipv6.conf.default.disable_ipv6']!=='1'||raw.Mounts?.length!==1||raw.Mounts[0].Source!==directory||raw.Mounts[0].Destination!=='/zap/wrk'||raw.Mounts[0].RW!==false)throw fail('ACTIVE_SCANNER_SECURITY_BLOCKED');
  return true;
}
function trustedNetworkEvidence(resources, authorization, scannerId) {
  const e=resources?.runtimeObservation;
  const clientId=resources?.acceptanceClientId||authorization.acceptanceClientId;
  if(!e || !clientId || e.verification!=='RUNTIME_OBSERVED' || e.complete!==true || e.independent!==true || e.scannerContainerId!==clientId || e.scannerNetworkId!==authorization.scannerNetworkId || e.ipv6!==false || e.directTcpBypass!==false || !e.routes) throw fail('ACTIVE_NAMESPACE_BLOCKED');
  if(e.namespaceScope!=='ZAP_SHARED_NETWORK_NAMESPACE'||e.namespaceEvidence?.zapContainerId!==scannerId||e.namespaceEvidence?.helperId!==clientId||e.namespaceEvidence?.equivalent!==true||e.namespaceEvidence?.source!=='LIVE_PROC_SELF_NS_NET')throw fail('ACTIVE_NAMESPACE_BLOCKED');
  return e;
}
class ActiveZapRuntime {
  constructor({adapter,lifecycle,scanId,catalog=require('../config/active-runtime-artifacts.json'),offline=false}={}) {
    if(!adapter || !lifecycle || !/^[a-z0-9_.-]{1,40}$/.test(scanId||''))throw fail('ACTIVE_RUNTIME_BLOCKED');
    if(offline ? process.env.NODE_ENV!=='test' : !isRuntimeAdapter(adapter))throw fail('ACTIVE_RUNTIME_BLOCKED');
    this.adapter=adapter;this.lifecycle=lifecycle;this.scanId=scanId;this.catalog=catalog;this.offline=offline;this.pending=null;
  }
  async preflight(authorization){
    if(!this.offline)require('./activeDastCommissioning').assertAuthorizationReady(authorization,this.catalog);
    capabilities(this.catalog,{commissioning:authorization.authorizationState==='COMMISSIONING'});require('./module2ActiveDast').validateAuthorization(authorization,authorization);if(authorization.zapImageDigest!==this.catalog.zap.imageId)throw fail('ACTIVE_IMAGE_MISMATCH');
    await require('./activeRuntimeArtifacts').verifyAvailable(this.adapter,this.catalog);
    const resources=this.lifecycle.resources.get(this.scanId);
    if(!resources||resources.diagnosticOnly||resources.fixtureResource?.id!==authorization.fixtureContainerId)throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    const networks=await Promise.all(resources.owned.networks.map(ref=>inspectOwnedNetwork(this.adapter,ref))),scannerNetwork=networks.find(n=>n.id===authorization.scannerNetworkId);
    if(!scannerNetwork)throw fail('ACTIVE_NAMESPACE_BLOCKED');
    const gateway=(await this.adapter.inspect([resources.gatewayId],'container')).normalized;verifyMemberships(gateway,networks);
    const proxy=`http://${gateway.networks[scannerNetwork.name].IPAddress}:3128`;
    await this.verifyFixture({authorization,resources,scannerNetwork,proxy});
    return {verified:true,scannerNamespace:'REQUIRES_FRESH_SCANNER_BINDING'};
  }
  async provision({authorization,signal}) {
    const paused=retained.get(this);
    if(paused){
      if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
      if(paused.claimed)throw fail('ACTIVE_RETAINED_SCANNER_BLOCKED');
      this.retainedIdentity(authorization);
      if(!require('./module2ActiveDast').isIssuedAuthorization(authorization)||require('./module2ActiveDast').isBaselineAuthorization(authorization)||!require('./activeDastCommissioning').activeAllowed(authorization))throw fail('COMMISSIONING_ACTIVE_AUTHORIZATION_BLOCKED');
      await this.verifyRetained(authorization);if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
      const r=sessions.get(paused.session);if(paused.claimed)throw fail('ACTIVE_RETAINED_SCANNER_BLOCKED');paused.claimed=true;
      r.authorization=authorization;r.baselineOnly=false;r.reusing=true;r.scanInvoked=false;r.bindingPending=true;
      r.timings.continuationAcceptedAt=Date.now();
      return paused.session;
    }
    if(!this.offline)require('./activeDastCommissioning').assertAuthorizationReady(authorization,this.catalog);
    capabilities(this.catalog,{commissioning:authorization.authorizationState==='COMMISSIONING'});
    if(!this.offline&&authorization.zapImageDigest!==this.catalog.zap.imageId)throw fail('ACTIVE_IMAGE_MISMATCH');
    if(!require('./activeDastCommissioning').runtimeAllowed(authorization)||signal?.aborted)throw fail('ACTIVE_CANCELLED');
    for(const image of [this.catalog.zap,this.catalog.fixture]) {
      const out=await this.adapter.run(['image','inspect',image.reference]);
      const value=JSON.parse(out.stdout);const observed=Array.isArray(value)?value[0]:value;
      if(out.exitCode!==0||out.stderr!==''||observed?.Id!==image.imageId||observed.Architecture!==image.architecture||observed.Os!==image.os)throw fail('ACTIVE_IMAGE_MISMATCH');
      if(image===this.catalog.fixture && image.reference.startsWith('sha256:')) require('./dastFixture').verifyPythonImage(observed);
      else if(image===this.catalog.zap&&image.reference.startsWith('sha256:'))require('./zapContainmentDiagnostic').verifyZapImage(observed);
      else if(!observed.RepoDigests?.includes(image.reference))throw fail('ACTIVE_IMAGE_MISMATCH');
      if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
    }
    const resources=this.lifecycle.resources.get(this.scanId);
    if(!resources || resources.diagnosticOnly===true || !resources.fixtureResource?.id || resources.fixtureResource.id!==authorization.fixtureContainerId || !resources.owned?.networks?.some(n=>n.id===authorization.scannerNetworkId))throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    const session={};const record={resources,authorization,directory:null,scannerId:null,files:new Map(),apiKey:crypto.randomBytes(32).toString('hex'),timings:{provisionStartedAt:Date.now()}};sessions.set(session,record);this.pending=session;
    const networks=await Promise.all(resources.owned.networks.map(ref=>inspectOwnedNetwork(this.adapter,ref)));
    const scanner=networks.find(n=>n.id===authorization.scannerNetworkId);
    const gateway=(await this.adapter.inspect([resources.gatewayId],'container')).normalized;
    verifyMemberships(gateway,networks);
    const proxy=`http://${gateway.networks[scanner.name].IPAddress}:3128`;
    record.proxy=proxy;record.scannerNetwork=scanner;
    record.directory=await fs.mkdtemp(path.join(os.tmpdir(),`cs-active-${this.scanId}-`));await fs.chmod(record.directory,0o700);
    const stat=await fs.lstat(record.directory);record.directoryIdentity={ino:stat.ino,dev:stat.dev,uid:stat.uid};
    // Artifacts are finalized before the readonly mount is created in scan().
    await this.verifyFixture(record);
    return session;
  }
  retainedIdentity(authorization){
    const paused=retained.get(this),r=paused&&sessions.get(paused.session),a=r?.authorization;
    if(!r||paused.claimed||!r.scannerId||!r.binding||!r.baselineOnly||this.lifecycle.states?.get(this.scanId)!=='READY'||a.expiresAt<=Date.now()||authorization.expiresAt>Date.now()+300000||authorization.expiresAt>a.expiresAt||authorization.expiresAt<=Date.now())throw fail('ACTIVE_RETAINED_SCANNER_BLOCKED');
    if(this.lifecycle.resources.get(this.scanId)!==r.resources||r.resources.diagnosticOnly===true||r.resources.fixtureResource?.id!==authorization.fixtureContainerId||!r.resources.owned?.networks?.some(n=>n.id===authorization.scannerNetworkId))throw fail('ACTIVE_RETAINED_SCANNER_BLOCKED');
    for(const key of ['projectId','executionId','userId','fixtureKind','fixtureContainerId','scannerNetworkId','gatewayContainerId','hostname','ip','port','scheme','routes','policies','zapImageDigest','fixtureImageDigest','gatewayImageDigest'])if(JSON.stringify(a[key])!==JSON.stringify(authorization[key]))throw fail('ACTIVE_RETAINED_SCANNER_BLOCKED');
    if(authorization.retainedScannerId!==undefined&&authorization.retainedScannerId!==r.scannerId)throw fail('ACTIVE_RETAINED_SCANNER_BLOCKED');
    return Object.freeze({scannerId:r.scannerId,expiresAt:a.expiresAt});
  }
  async verifyRetained(authorization){
    const identity=this.retainedIdentity(authorization),session=retained.get(this).session,r=sessions.get(session),start=performance.now();
    if(!this.offline)require('./activeDastCommissioning').assertAuthorizationReady(authorization,this.catalog);
    capabilities(this.catalog,{commissioning:authorization.authorizationState==='COMMISSIONING'});
    require('./module2ActiveDast').validateAuthorization(authorization,authorization);
    if(authorization.zapImageDigest!==this.catalog.zap.imageId)throw fail('ACTIVE_IMAGE_MISMATCH');
    // Image metadata is independent; complete it alongside the single full
    // live verification. verify() already checks fixture/gateway/membership,
    // policy, mounts, scanner and namespace. Never reuse an earlier snapshot.
    await verifiedReads([
      ()=>require('./activeRuntimeArtifacts').verifyAvailable(this.adapter,this.catalog),
      ()=>this.verify(session,r.authorization)
    ]);
    require('./module2ActiveDast').validateAuthorization(authorization,authorization);
    // Recheck after asynchronous inspection; expiry or a concurrent claim cannot
    // be hidden by a previously valid object or route snapshot.
    this.retainedIdentity(authorization);r.timings.lastReuseVerificationMs=Math.round(performance.now()-start);
    return {verified:true,reusableScanner:true,scannerId:identity.scannerId};
  }
  async verifyFixture(r) {
    const a=r.authorization,ref=r.resources.fixtureResource;
    const [fixtureOut,networks,native,gatewayObserved,gatewayOut]=await verifiedReads([
      ()=>this.adapter.inspect([ref.id],'container'),
      ()=>verifiedReads(r.resources.owned.networks.map(n=>()=>inspectOwnedNetwork(this.adapter,n))),
      ()=>this.adapter.run(['inspect','--format','{{json .}}',ref.id]),
      ()=>this.adapter.inspect([r.resources.gatewayId],'container'),
      ()=>this.adapter.run(['inspect','--format','{{json .}}',r.resources.gatewayId])
    ]);
    const fixture=fixtureOut.normalized;
    const fixtureNetwork=networks.find(n=>n.role==='fixture')||networks.find(n=>n.id===ref.networkId);
    if(!fixtureNetwork)throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    verifyMemberships(fixture,[fixtureNetwork]);
    if(fixture.objectId!==a.fixtureContainerId || fixture.imageId!==this.catalog.fixture.imageId || fixture.imageDigest!==this.catalog.fixture.reference || fixture.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}` || fixture.labels?.['cloudsentinel.role']!=='fixture' || fixture.state?.Running!==true || fixture.networks[fixtureNetwork.name]?.IPAddress!==a.ip || !fixture.security?.readOnly || fixture.security.privileged || fixture.security.capAdd.length)throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    const raw=JSON.parse(native.stdout);
    if(native.exitCode!==0||native.stderr!=='')throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    if(this.catalog.fixture.reference.startsWith('sha256:')) require('./dastFixture').verifyPythonRuntime(raw,{id:a.fixtureContainerId,owner:`cloudsentinel-${this.scanId}`,scanId:this.scanId,networkId:fixtureNetwork.id});
    if(Object.keys(raw.HostConfig?.PortBindings||{}).length || Object.values(raw.NetworkSettings?.Ports||{}).some(v=>Array.isArray(v)&&v.length))throw fail('ACTIVE_PUBLISHED_FIXTURE_BLOCKED');
    if(a.authorizationState==='COMMISSIONING'&&r.resources.gatewayId!==a.gatewayContainerId)throw fail('ACTIVE_GATEWAY_MISMATCH');
    const gateway=gatewayObserved.normalized;
    verifyMemberships(gateway,networks);
    if(gateway.imageDigest!==require('./dastGateway').IMAGE || gateway.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}` || gateway.labels?.['cloudsentinel.role']!=='gateway' || gateway.state?.Running!==true || `http://${gateway.networks[r.scannerNetwork.name]?.IPAddress}:3128`!==r.proxy)throw fail('ACTIVE_GATEWAY_MISMATCH');
    const g=JSON.parse(gatewayOut.stdout),h=g.HostConfig||{};
    if(gatewayOut.exitCode!==0||gatewayOut.stderr!==''||g.Config?.User!==`${process.getuid()}:${process.getgid()}`||h.ReadonlyRootfs!==true||h.Privileged||h.CapAdd?.length||!h.CapDrop?.includes('ALL')||!h.SecurityOpt?.includes('no-new-privileges:true')||h.Memory!==268435456||h.NanoCpus!==1000000000||h.PidsLimit!==64||h.NetworkMode!==r.scannerNetwork.id||h.PublishAllPorts||Object.keys(h.PortBindings||{}).length||Object.values(g.NetworkSettings?.Ports||{}).some(Boolean)||g.Mounts?.length!==1||g.Mounts[0].Source!==r.resources.staged.filePath||g.Mounts[0].Destination!==r.resources.staged.containerPath||g.Mounts[0].RW!==false)throw fail('ACTIVE_GATEWAY_SECURITY_BLOCKED');
    const expected=proxyPolicy(a),actual=await this.adapter.run(['exec',gateway.objectId,'cat',r.resources.staged.containerPath]);
    if(actual.exitCode!==0 || actual.stderr!=='' || actual.stdout!==expected)throw fail('ACTIVE_PATH_POLICY_BLOCKED');
  }
  async verify(session,authorization) {
    const r=sessions.get(session);if(!r || r.authorization!==authorization)throw fail('ACTIVE_SESSION_BLOCKED');
    if(authorization.authorizationState==='COMMISSIONING'){require('./module2ActiveDast').validateAuthorization(authorization,authorization);if(!require('./activeDastCommissioning').runtimeAllowed(authorization))throw fail('COMMISSIONING_RUNTIME_BLOCKED');}
    if(r.directory) {
      const s=await fs.lstat(r.directory),id=r.directoryIdentity;
      if(!s.isDirectory()||s.isSymbolicLink()||s.ino!==id.ino||s.dev!==id.dev||s.uid!==id.uid||(s.mode&0o777)!==0o700)throw fail('ACTIVE_ARTIFACT_MISMATCH');
    }
    await this.verifyFixture(r);
    if(!r.scannerId)return;
    const [scannerOut,rawScanner,network]=await verifiedReads([
      ()=>this.adapter.inspect([r.scannerId],'container'),
      ()=>this.adapter.run(['inspect','--format','{{json .}}',r.scannerId]),
      ()=>inspectOwnedNetwork(this.adapter,r.resources.owned.networks.find(n=>n.id===authorization.scannerNetworkId))
    ]);
    const scanner=scannerOut.normalized;if(rawScanner.exitCode!==0||rawScanner.stderr!=='')throw fail('ACTIVE_SCANNER_IDENTITY_BLOCKED');assertScannerSecurity(JSON.parse(rawScanner.stdout),{networkId:r.authorization.scannerNetworkId,directory:r.directory});
    verifyMemberships(scanner,[network]);
    if(scanner.objectId!==r.scannerId || scanner.imageId!==this.catalog.zap.imageId || scanner.imageDigest!==this.catalog.zap.reference || scanner.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}` || scanner.labels?.['cloudsentinel.role']!=='active-zap' || scanner.state?.Running!==true || !scanner.security.readOnly || scanner.security.privileged || scanner.security.capAdd.length || !scanner.security.capDrop.includes('ALL') || !scanner.security.securityOpt.includes('no-new-privileges:true') || scanner.mounts.length!==1 || scanner.mounts[0].Source!==r.directory || scanner.mounts[0].Destination!=='/zap/wrk' || scanner.mounts[0].RW!==false)throw fail('ACTIVE_SCANNER_IDENTITY_BLOCKED');
    // The pinned ZAP image has no ip or nc. Namespace/route evidence must come
    // from the lifecycle-owned, independently verified acceptance client; never
    // downgrade this requirement to Docker network metadata alone.
    if(!r.bindingPending){trustedNetworkEvidence(r.resources,r.authorization,r.scannerId);await require('./activeScannerBinding').verify(this.adapter,r.binding,r.scannerId);}
    for(const [name,digest] of r.files){const out=await this.adapter.run(['exec',r.scannerId,'sha256sum',`/zap/wrk/${name}`]);if(out.exitCode!==0||out.stderr!==''||out.stdout.trim()!==`${digest}  /zap/wrk/${name}`)throw fail('ACTIVE_ARTIFACT_MISMATCH');}
  }
  async verifyCommissioningTraffic(session,{signal}={}) {
    const r=sessions.get(session);
    if(!r||r.authorization.authorizationState!=='COMMISSIONING')throw fail('COMMISSIONING_AUTHORIZATION_BLOCKED');
    if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
    await this.verify(session,r.authorization);
    const scanner=(await this.adapter.inspect([r.scannerId],'container')).normalized;
    const clientIp=scanner.networks[r.scannerNetwork.name]?.IPAddress;
    if(isIP(clientIp)!==4)throw fail('ACTIVE_SCANNER_IDENTITY_BLOCKED');
    r.commissioningTrafficTask=require('./zapCommissioningTraffic').collect({adapter:this.adapter,scannerId:r.scannerId,gatewayId:r.resources.gatewayId,clientIp,authorization:r.authorization,apiKey:r.apiKey,proxy:r.proxy,requirePassive:r.baselineOnly===true,verify:()=>this.verify(session,r.authorization),signal});
    r.commissioningTraffic=await r.commissioningTrafficTask;
    return r.commissioningTraffic;
  }
  async scan(session,{plans,signal,maxRequestsPerSecond,maxConcurrency}) {
    const r=sessions.get(session);if(!r || r.scanInvoked || (r.scannerId&&!r.reusing) || !Array.isArray(plans)||plans.length!==(r.authorization.authorizationState==='COMMISSIONING'?1:2)||maxRequestsPerSecond!==2||maxConcurrency!==1)throw fail('ACTIVE_SESSION_BLOCKED');
    r.scanInvoked=true;const scanStartedAt=performance.now();
    if(!require('./activeDastCommissioning').runtimeAllowed(r.authorization)||(require('./module2ActiveDast').isBaselineAuthorization(r.authorization)&&r.baselineOnly!==true))throw fail('COMMISSIONING_ACTIVE_AUTHORIZATION_BLOCKED');
    await this.verify(session,r.authorization);
    // The supplied plans must exactly match the established policy generator.
    const expected=r.baselineOnly?[require('./dastActiveScanner').commissioningPlan(`http://${r.authorization.hostname}:18080`,{baseline:true})]:require('./module2ActiveDast').plans(r.authorization);
    if(JSON.stringify(plans)!==JSON.stringify(expected))throw fail('ACTIVE_POLICY_CAPABILITIES_BLOCKED');
    for(let i=0;i<plans.length;i++) {
      const index=r.reusing?1:i,name=`plan-${index}.yaml`;const plan=plans[i].replace('reportDir: /zap/wrk','reportDir: /tmp').replace('reportFile: report.json',`reportFile: report-${index}.json`);
      await fs.writeFile(path.join(r.directory,name),plan,{flag:'wx',mode:0o400});r.files.set(name,hash(plan));
    }
    if(r.authorization.authorizationState==='COMMISSIONING'&&!r.reusing)await require('./zapCommissioningTraffic').stage(r.directory,r.files);
    r.bindingPending=true;
    if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
    if(!r.reusing){
    r.creationAttempted=true;
    r.createTask=this.adapter.run(runArguments({scanId:this.scanId,networkId:r.authorization.scannerNetworkId,image:this.catalog.zap.reference,directory:r.directory,proxy:r.proxy,hostname:r.authorization.hostname,ip:r.authorization.ip}));const created=await r.createTask;
    r.scannerId=created.objectId||created.stdout.trim();if(!/^[a-f0-9]{64}$/.test(r.scannerId))throw fail('ACTIVE_SCANNER_IDENTITY_BLOCKED');
    }
    if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
    await this.verify(session,r.authorization);
    if(r.reusing&&r.binding)require('./activeScannerBinding').revoke(r.binding.token);
    r.bindingTask=require('./activeScannerBinding').bind({adapter:this.adapter,lifecycle:this.lifecycle,scanId:this.scanId,authorization:r.authorization,scannerId:r.scannerId,imageId:this.catalog.zap.imageId,directory:r.directory,signal});r.binding=await r.bindingTask;r.bindingPending=false;
    if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
    await this.verify(session,r.authorization);
    if(!r.reusing){
    const seeded=await this.adapter.run(['exec',r.scannerId,...profileBootstrapArguments()]);
    if(seeded.exitCode!==0 || seeded.stderr!=='')throw fail('ZAP_PROFILE_NOT_READY');
    }
    const seedPath=`${writable.profilePath}/${writable.profileSeed.name}`;
    const seedHash=await this.adapter.run(['exec',r.scannerId,'sha256sum',seedPath]);
    if(seedHash.exitCode!==0 || seedHash.stderr!=='' || seedHash.stdout.trim()!==`${writable.profileSeed.sha256}  ${seedPath}`)throw fail('ZAP_PROFILE_NOT_READY');
    const jvmArgs=jvmBootstrapArguments();
    if(!r.reusing){
    const jvmSeed=await this.adapter.run(['exec',r.scannerId,...jvmArgs]);
    if(jvmSeed.exitCode!==0 || jvmSeed.stderr!=='')throw fail('ZAP_PREFERENCES_NOT_READY');
    }
    const jvmPath=`${writable.javaPreferencesRoot}/${writable.jvmPropertiesName}`;
    const jvmHash=await this.adapter.run(['exec',r.scannerId,'sha256sum',jvmPath]);
    if(jvmHash.exitCode!==0 || jvmHash.stderr!=='' || jvmHash.stdout.trim()!==`${jvmArgs.at(-1)}  ${jvmPath}`)throw fail('ZAP_PREFERENCES_NOT_READY');
    r.timings.namespaceAndBootstrapMs=Math.round(performance.now()-scanStartedAt);
    const stop=()=>{(async()=>{
      const observed=(await this.adapter.inspect([r.scannerId],'container')).normalized;
      if(observed.objectId!==r.scannerId||observed.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}`||observed.labels?.['cloudsentinel.role']!=='active-zap')throw fail('ACTIVE_CLEANUP_OWNERSHIP');
      await this.adapter.run(['stop','--time','1',r.scannerId]);
    })().catch(()=>{});};
    signal?.addEventListener('abort',stop,{once:true});
    try {
      if(r.authorization.authorizationState==='COMMISSIONING'){
        const started=performance.now();
        if(r.reusing){const prepared=await this.adapter.run(require('./zapCommissioningTraffic').command(r.scannerId,'prepare-reuse',{}));if(prepared.exitCode!==0||prepared.stderr||prepared.stdout.trim()!=='{"prepared":true}')throw fail('ACTIVE_RETAINED_SCANNER_BLOCKED');}
        await this.verifyCommissioningTraffic(session,{signal});r.timings.daemonAndTrafficMs=Math.round(performance.now()-started);
      }
      const sites=[];
      for(let i=0;i<plans.length;i++) {
        const index=r.reusing?1:i,planStartedAt=performance.now();
        if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
        await this.verify(session,r.authorization);
        if(!r.baselineOnly&&r.authorization.authorizationState==='COMMISSIONING')require('./commissioningBudget').beforePlan(signal);
        const proxy=new URL(r.proxy);
        const command=['exec',r.scannerId,'zap.sh','-cmd','-host','127.0.0.1','-port','8090','-config',writable.callbackBinding,'-config','api.disablekey=false','-config',`api.key=${r.apiKey}`,'-dir','/home/zap/.ZAP','-config',`connection.proxyChain.enabled=true`,'-config',`connection.proxyChain.hostName=${proxy.hostname}`,'-config','connection.proxyChain.port=3128','-autorun',`/zap/wrk/plan-${index}.yaml`];
        let out;
        if(r.authorization.authorizationState==='COMMISSIONING'){
          r.commissioningPlanTask=require('./zapCommissioningTraffic').executePlan({adapter:this.adapter,scannerId:r.scannerId,gatewayId:r.resources.gatewayId,index,args:command.slice(3),authorization:r.authorization,verify:()=>this.verify(session,r.authorization),signal});
          out=await r.commissioningPlanTask;
        }else out=await this.adapter.run(command);
        r.evidenceOutput=out;
        const initializationFailure=startupFailure(out.stdout,out.stderr);
        const commandFailure=initializationFailure||(out.exitCode!==0 || Buffer.byteLength(out.stdout||'')>1048576?'ACTIVE_SCAN_INCOMPLETE':null);
        if(commandFailure){
          const error=fail(commandFailure);
          // Native output must survive the baseline/failure cleanup path. Never
          // replace the original validation failure if private persistence fails.
          try{error.automationEvidenceFile=await require('./zapAutomationEvidence').save({authorization:r.authorization,scannerId:r.scannerId,index,output:out,reason:commandFailure,secrets:[r.apiKey]});}
          catch(_){error.automationEvidenceError='ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED';}
          throw error;
        }
        r.timings.autorunMs=Math.round(performance.now()-planStartedAt);const reportStartedAt=performance.now();
        const report=await this.adapter.run(['exec',r.scannerId,'cat',`/tmp/report-${index}.json`]);
        if(report.exitCode!==0||report.stderr!==''||Buffer.byteLength(report.stdout)>2097152)throw fail('ACTIVE_REPORT_INVALID');
        r.evidenceReport=report.stdout;
        const parsed=JSON.parse(report.stdout);if(!Array.isArray(parsed.site))throw fail('ACTIVE_REPORT_INVALID');sites.push(...parsed.site);
        await this.verify(session,r.authorization);
        r.timings.reportAndVerificationMs=Math.round(performance.now()-reportStartedAt);
      }
      return {completed:true,exitCode:0,report:{site:sites},timings:{...r.timings,totalMs:Math.round(performance.now()-scanStartedAt),source:'MONOTONIC_RUNTIME_CLOCK',reusedScanner:r.reusing===true},...(r.commissioningTraffic?{commissioningTraffic:r.commissioningTraffic}:{})};
    } finally {signal?.removeEventListener('abort',stop);}
  }
  async baseline({authorization,signal}) {
    if(!require('./activeDastCommissioning').validate(authorization,authorization)||!require('./module2ActiveDast').isBaselineAuthorization(authorization))throw fail('ACTIVE_AUTHORIZATION_BLOCKED');
    const session=await this.provision({authorization,signal}),r=sessions.get(session);r.baselineOnly=true;
    try{
      const result=await this.scan(session,{plans:[require('./dastActiveScanner').commissioningPlan(`http://${authorization.hostname}:18080`,{baseline:true})],signal,maxRequestsPerSecond:2,maxConcurrency:1});
      if(result.completed!==true||result.exitCode!==0||result.commissioningTraffic?.verified!==true)throw fail('COMMISSIONING_BASELINE_BLOCKED');
      await this.verify(session,authorization);
      retained.set(this,{session,claimed:false});
      return result;
    }catch(error){r.preserveLifecycle=false;await this.cleanup(session).catch(()=>{});throw error;}
  }
  async cleanup(session=this.pending) {
    if(this.cleanupTask)return this.cleanupTask;
    this.cleanupTask=this.cleanupOwned(session);
    try{return await this.cleanupTask;}finally{this.cleanupTask=null;}
  }
  async cleanupOwned(session=this.pending) {
    retained.delete(this);const cleanupStartedAt=performance.now();
    const r=sessions.get(session);if(!r)return {cleaned:true,residual:[]};const residual=[];
    if(r.createTask)await r.createTask.catch(()=>{});
    if(r.bindingTask)await r.bindingTask.catch(()=>{});
    if(r.commissioningTrafficTask)await r.commissioningTrafficTask.catch(()=>{});
    if(r.commissioningPlanTask)await r.commissioningPlanTask.catch(()=>{});
    if(r.creationAttempted&&!r.scannerId)try{
      const n=(await this.adapter.inspect([`cs-zap-${this.scanId}`],'container')).normalized;
      if(!/^[a-f0-9]{64}$/.test(n.objectId)||n.imageId!==this.catalog.zap.imageId||n.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}`||n.labels?.['cloudsentinel.role']!=='active-zap')throw fail('ACTIVE_CLEANUP_OWNERSHIP');r.scannerId=n.objectId;
    }catch(error){if(error.code!=='MISSING_RESOURCE')return {cleaned:false,residual:[{type:'uncertain-active-zap',error:error.code||'CLEANUP_FAILED'}]};}
    if(r.scannerId&&r.resources.activeHelperAttempted&&!r.resources.clientResource)try{
      const n=(await this.adapter.inspect([require('./acceptanceNames').containerName(this.scanId,'client')],'container')).normalized;
      if(n.imageDigest!==require('./dastAcceptanceClient').IMAGE||n.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}`||n.labels?.['cloudsentinel.role']!=='acceptance-client'||n.security?.networkMode!==`container:${r.scannerId}`)throw fail('ACTIVE_CLEANUP_OWNERSHIP');
      r.resources.clientResource={id:n.objectId,owner:`cloudsentinel-${this.scanId}`};
    }catch(error){if(error.code!=='MISSING_RESOURCE')return {cleaned:false,residual:[{type:'uncertain-namespace-helper',error:error.code||'CLEANUP_FAILED'}]};}
    // Capture before the first scanner/helper/gateway removal. Evidence failure
    // never suppresses ownership-safe cleanup, and cannot become acceptance PASS.
    let evidenceResult=null;
    if(r.scannerId&&!r.baselineOnly){
      try {
        const ownedScanner=(await this.adapter.inspect([r.scannerId],'container')).normalized;
        const ownedGateway=(await this.adapter.inspect([r.resources.gatewayId],'container')).normalized;
        if(ownedScanner.objectId!==r.scannerId||ownedScanner.imageId!==this.catalog.zap.imageId||ownedScanner.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}`||ownedGateway.objectId!==r.resources.gatewayId||ownedGateway.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}`)throw fail('ACTIVE_EVIDENCE_IDENTITY');
        const index=r.reusing?1:0;
        const read=async file=>{try{const v=await this.adapter.run(['exec',r.scannerId,'cat',file]);return v.exitCode===0&&!v.stderr?v.stdout:null;}catch(_){return null;}};
        const automation=r.evidenceOutput||{stdout:await read(`/tmp/commissioning-plan-${index}.log`),stderr:null,exitCode:null};
        const rawReport=r.evidenceReport||await read(`/tmp/report-${index}.json`);
        let parsed=null;try{parsed=JSON.parse(rawReport);}catch(_){}
        let access=null;try{const v=await this.adapter.run(['exec',r.resources.gatewayId,'cat','/tmp/cloudsentinel-active-access.log']);if(v.exitCode===0&&!v.stderr)access=v.stdout;}catch(_){}
        const client=(await this.adapter.inspect([r.scannerId],'container')).normalized;
        const member=client.networks?.[r.scannerNetwork.name];
        const requestEvidence=require('./activeDastEvidence').requests(access,{clientIp:member?.IPAddress,hostname:r.authorization.hostname});
        evidenceResult=await require('./activeDastEvidence').save({projectId:r.authorization.projectId,executionId:r.authorization.executionId,requests:requestEvidence,artifacts:{automation,report:rawReport,alerts:parsed?.site?parsed.site.flatMap(s=>s.alerts||[]):null,requests:requestEvidence,identity:{scannerId:r.scannerId,gatewayId:r.resources.gatewayId,fixtureId:r.resources.fixtureResource?.id,networkId:r.authorization.scannerNetworkId,zapImage:this.catalog.zap.imageId,fixtureImage:r.authorization.fixtureImageDigest,gatewayImage:r.authorization.gatewayImageDigest,executionExpiresAt:r.authorization.expiresAt,grantId:r.authorization.grantId||null,approvedRules:POLICY.approvedPluginIds,leaseId:r.authorization.leaseId||null,timings:r.timings}}},{secrets:[r.apiKey]});
      }catch(_){
        try{evidenceResult=await require('./activeDastEvidence').save({projectId:r.authorization.projectId,executionId:r.authorization.executionId,artifacts:{identity:{state:'IDENTITY_OR_CAPTURE_UNVERIFIED',scannerId:r.scannerId,gatewayId:r.resources.gatewayId}}});}
        catch(_){evidenceResult={state:'WRITE_FAILED',acceptance:'BLOCKED'};}
      }
    }
    if(r.scannerId&&r.resources.clientResource)try{
      const out=await require('./dastAcceptanceClient').cleanup(this.adapter,r.resources.clientResource);
      if(!out.cleaned)throw fail('ACTIVE_HELPER_CLEANUP_FAILED');delete r.resources.clientResource;
      if(r.binding)require('./activeScannerBinding').revoke(r.binding.token);
    }catch(error){return {cleaned:false,residual:[{type:'namespace-helper',error:error.code||'CLEANUP_FAILED'}]};}
    if(r.scannerId)try {
      const scanner=(await this.adapter.inspect([r.scannerId],'container')).normalized;
      if(scanner.objectId!==r.scannerId||scanner.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}`||scanner.labels?.['cloudsentinel.role']!=='active-zap')throw fail('ACTIVE_CLEANUP_OWNERSHIP');
      await this.adapter.run(['stop',r.scannerId]);await this.adapter.run(['rm',r.scannerId]);r.scannerId=null;
    } catch(error){if(error.code==='MISSING_RESOURCE')r.scannerId=null;else residual.push({type:'active-zap',id:r.scannerId,error:error.code||'CLEANUP_FAILED'});}
    if(!r.scannerId) {
      if(!r.preserveLifecycle){const result=await this.lifecycle.cleanup(this.scanId);residual.push(...(result.residual||[]));}
      if(r.directory)try {
        const s=await fs.lstat(r.directory),id=r.directoryIdentity;
        if(s.isSymbolicLink()||s.ino!==id.ino||s.dev!==id.dev||s.uid!==id.uid)throw fail('ACTIVE_CLEANUP_OWNERSHIP');
        for(const name of await fs.readdir(r.directory)){if(!r.files.has(name))throw fail('ACTIVE_CLEANUP_OWNERSHIP');const f=path.join(r.directory,name);if((await fs.lstat(f)).isSymbolicLink()||hash(await fs.readFile(f))!==r.files.get(name))throw fail('ACTIVE_CLEANUP_OWNERSHIP');await fs.unlink(f);r.files.delete(name);}
        await fs.rmdir(r.directory);r.directory=null;
      }catch(error){residual.push({type:'active-artifact',error:error.code||'CLEANUP_FAILED'});}
    }
    if(!residual.length){sessions.delete(session);this.pending=null;}
    return {cleaned:!residual.length,residual,durationMs:Math.round(performance.now()-cleanupStartedAt),...(evidenceResult?{evidence:evidenceResult}:{})};
  }
}
module.exports={ActiveZapRuntime,capabilities,proxyPolicy,runArguments,assertScannerSecurity};
