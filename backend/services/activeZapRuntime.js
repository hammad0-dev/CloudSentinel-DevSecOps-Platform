'use strict';
// Production scanner control for an existing, grant-bound live lifecycle.
// Historical acceptance JSON or caller-provided container snapshots are never used.
const fs=require('fs/promises'),path=require('path'),os=require('os'),crypto=require('crypto');
const {isIP}=require('net');
const {isRuntimeAdapter}=require('./dockerAdapter');
const {inspectOwnedNetwork,verifyMemberships}=require('./ownedDockerNetworks');
const {POLICY}=require('./dastActiveScanner');
const {STORAGE,homeTmpfs,assertInitialized,startupFailure}=require('./zapInitialization');
const sessions=new WeakMap();
const fail=code=>Object.assign(new Error(code),{code,nonRetryable:true});
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function capabilities(catalog) {
  const z=catalog?.zap,f=catalog?.fixture,c=z?.capabilities;
  for(const item of [z,f])if(!item || !/^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$/.test(item.reference||'') || item.imageId!==item.reference.split('@')[1] || item.architecture!=='amd64' || item.os!=='linux')throw fail('ACTIVE_RUNTIME_BLOCKED');
  if(!c || c.imageId!==z.imageId || c.verified!==true || JSON.stringify([...(c.activeRuleIds||[])].sort())!==JSON.stringify([...POLICY.approvedPluginIds].sort()) || !['automation','spider','activeScan','report','proxy','rateLimit','sha256sum','python3'].every(k=>c.commands?.includes(k)) || c.commands?.includes('ip') || c.commands?.includes('nc') || f.fixtureKind!=='cloudsentinel-vulnerable-v1')throw fail('ACTIVE_POLICY_CAPABILITIES_BLOCKED');
  const contract=c.runtimeContract;
  if(!contract || contract.apiBinding!=='LOOPBACK_ONLY' || contract.apiAuthentication!=='REQUIRED' || contract.maxRequestsPerSecond!==2 || contract.maxConcurrency!==1 || contract.spiderRateLimited!==true || contract.exactPathScope!==true || contract.jobCompletionVerified!==true || contract.timeoutVerified!==true || contract.cancellationVerified!==true || contract.exportFormat!=='traditional-json' || !/^[a-f0-9]{64}$/.test(contract.evidenceSha256||''))throw fail('ACTIVE_POLICY_CAPABILITIES_BLOCKED');
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
  return ['run','-d','--pull=never','--name',containerName,'--hostname',containerName,'--network',networkId,'--label',`cloudsentinel.owner=cloudsentinel-${scanId}`,'--label',`cloudsentinel.scan=${scanId}`,'--label','cloudsentinel.role=active-zap','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','128','--memory',`${STORAGE.memoryMiB}m`,'--cpus','1','--sysctl','net.ipv6.conf.all.disable_ipv6=1','--sysctl','net.ipv6.conf.default.disable_ipv6=1','--user','1000:1000','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=1777','--tmpfs',homeTmpfs(),'--add-host',`${containerName}:127.0.0.1`,'--add-host',`${hostname}:${ip}`,'--mount',`type=bind,src=${directory},dst=/zap/wrk,readonly`,'--entrypoint','/bin/sh',image,'-c','sleep 900'];
}
function trustedNetworkEvidence(resources, authorization) {
  const e=resources?.runtimeObservation;
  const clientId=resources?.acceptanceClientId||authorization.acceptanceClientId;
  if(!e || !clientId || e.verification!=='RUNTIME_OBSERVED' || e.complete!==true || e.independent!==true || e.scannerContainerId!==clientId || e.scannerNetworkId!==authorization.scannerNetworkId || e.ipv6!==false || e.directTcpBypass!==false || !e.routes) throw fail('ACTIVE_NAMESPACE_BLOCKED');
  return e;
}
class ActiveZapRuntime {
  constructor({adapter,lifecycle,scanId,catalog=require('../config/active-runtime-artifacts.json'),offline=false}={}) {
    if(!adapter || !lifecycle || !/^[a-z0-9_.-]{1,40}$/.test(scanId||''))throw fail('ACTIVE_RUNTIME_BLOCKED');
    if(offline ? process.env.NODE_ENV!=='test' : !isRuntimeAdapter(adapter))throw fail('ACTIVE_RUNTIME_BLOCKED');
    this.adapter=adapter;this.lifecycle=lifecycle;this.scanId=scanId;this.catalog=catalog;this.offline=offline;this.pending=null;
  }
  async provision({authorization,signal}) {
    capabilities(this.catalog);
    if(process.env.DAST_ACTIVE_ENABLED!=='true'||signal?.aborted)throw fail('ACTIVE_CANCELLED');
    for(const image of [this.catalog.zap,this.catalog.fixture]) {
      const out=await this.adapter.run(['image','inspect',image.reference]);
      const value=JSON.parse(out.stdout);const observed=Array.isArray(value)?value[0]:value;
      if(out.exitCode!==0||out.stderr!==''||observed?.Id!==image.imageId||observed.Architecture!==image.architecture||observed.Os!==image.os||!observed.RepoDigests?.includes(image.reference))throw fail('ACTIVE_IMAGE_MISMATCH');
    }
    const resources=this.lifecycle.resources.get(this.scanId);
    if(!resources || !resources.fixtureResource?.id || resources.fixtureResource.id!==authorization.fixtureContainerId || !resources.owned?.networks?.some(n=>n.id===authorization.scannerNetworkId))throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    const session={};const record={resources,authorization,directory:null,scannerId:null,files:new Map(),apiKey:crypto.randomBytes(32).toString('hex')};sessions.set(session,record);this.pending=session;
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
  async verifyFixture(r) {
    const a=r.authorization,ref=r.resources.fixtureResource;
    const fixture=(await this.adapter.inspect([ref.id],'container')).normalized;
    const networks=await Promise.all(r.resources.owned.networks.map(n=>inspectOwnedNetwork(this.adapter,n)));
    const fixtureNetwork=networks.find(n=>n.role==='fixture')||networks.find(n=>n.id===ref.networkId);
    if(!fixtureNetwork)throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    verifyMemberships(fixture,[fixtureNetwork]);
    if(fixture.objectId!==a.fixtureContainerId || fixture.imageDigest!==this.catalog.fixture.reference || fixture.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}` || fixture.labels?.['cloudsentinel.role']!=='fixture' || fixture.state?.Running!==true || fixture.networks[fixtureNetwork.name]?.IPAddress!==a.ip || !fixture.security?.readOnly || fixture.security.privileged || fixture.security.capAdd.length)throw fail('ACTIVE_TARGET_IDENTITY_MISMATCH');
    const native=await this.adapter.run(['inspect','--format','{{json .}}',fixture.objectId]);
    const raw=JSON.parse(native.stdout);
    if(Object.keys(raw.HostConfig?.PortBindings||{}).length || Object.values(raw.NetworkSettings?.Ports||{}).some(v=>Array.isArray(v)&&v.length))throw fail('ACTIVE_PUBLISHED_FIXTURE_BLOCKED');
    const gateway=(await this.adapter.inspect([r.resources.gatewayId],'container')).normalized;
    verifyMemberships(gateway,networks);
    if(gateway.imageDigest!==require('./dastGateway').IMAGE || gateway.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}` || gateway.labels?.['cloudsentinel.role']!=='gateway' || gateway.state?.Running!==true || `http://${gateway.networks[r.scannerNetwork.name]?.IPAddress}:3128`!==r.proxy)throw fail('ACTIVE_GATEWAY_MISMATCH');
    const expected=proxyPolicy(a),actual=await this.adapter.run(['exec',gateway.objectId,'cat',r.resources.staged.containerPath]);
    if(actual.exitCode!==0 || actual.stderr!=='' || actual.stdout!==expected)throw fail('ACTIVE_PATH_POLICY_BLOCKED');
  }
  async verify(session,authorization) {
    const r=sessions.get(session);if(!r || r.authorization!==authorization)throw fail('ACTIVE_SESSION_BLOCKED');
    if(r.directory) {
      const s=await fs.lstat(r.directory),id=r.directoryIdentity;
      if(!s.isDirectory()||s.isSymbolicLink()||s.ino!==id.ino||s.dev!==id.dev||s.uid!==id.uid||(s.mode&0o777)!==0o700)throw fail('ACTIVE_ARTIFACT_MISMATCH');
    }
    await this.verifyFixture(r);
    if(!r.scannerId)return;
    const scanner=(await this.adapter.inspect([r.scannerId],'container')).normalized;
    const network=await inspectOwnedNetwork(this.adapter,r.resources.owned.networks.find(n=>n.id===authorization.scannerNetworkId));
    verifyMemberships(scanner,[network]);
    if(scanner.objectId!==r.scannerId || scanner.imageDigest!==this.catalog.zap.reference || scanner.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}` || scanner.labels?.['cloudsentinel.role']!=='active-zap' || scanner.state?.Running!==true || !scanner.security.readOnly || scanner.security.privileged || scanner.security.capAdd.length || !scanner.security.capDrop.includes('ALL') || !scanner.security.securityOpt.includes('no-new-privileges:true') || scanner.mounts.length!==1 || scanner.mounts[0].Source!==r.directory || scanner.mounts[0].Destination!=='/zap/wrk' || scanner.mounts[0].RW!==false)throw fail('ACTIVE_SCANNER_IDENTITY_BLOCKED');
    // The pinned ZAP image has no ip or nc. Namespace/route evidence must come
    // from the lifecycle-owned, independently verified acceptance client; never
    // downgrade this requirement to Docker network metadata alone.
    trustedNetworkEvidence(r.resources,r.authorization);
    for(const [name,digest] of r.files){const out=await this.adapter.run(['exec',r.scannerId,'sha256sum',`/zap/wrk/${name}`]);if(out.exitCode!==0||out.stderr!==''||out.stdout.trim()!==`${digest}  /zap/wrk/${name}`)throw fail('ACTIVE_ARTIFACT_MISMATCH');}
  }
  async scan(session,{plans,signal,maxRequestsPerSecond,maxConcurrency}) {
    const r=sessions.get(session);if(!r || r.scannerId || !Array.isArray(plans)||plans.length!==2||maxRequestsPerSecond!==2||maxConcurrency!==1)throw fail('ACTIVE_SESSION_BLOCKED');
    await this.verify(session,r.authorization);
    // The supplied plans must exactly match the established policy generator.
    const expected=require('./module2ActiveDast').ROUTES.map(p=>require('./dastActiveScanner').automationPlan(`http://${r.authorization.hostname}:18080${p}`));
    if(JSON.stringify(plans)!==JSON.stringify(expected))throw fail('ACTIVE_POLICY_CAPABILITIES_BLOCKED');
    for(let i=0;i<plans.length;i++) {
      const name=`plan-${i}.yaml`;const plan=plans[i].replace('reportDir: /zap/wrk','reportDir: /tmp').replace('reportFile: report.json',`reportFile: report-${i}.json`);
      await fs.writeFile(path.join(r.directory,name),plan,{flag:'wx',mode:0o400});r.files.set(name,hash(plan));
    }
    const created=await this.adapter.run(runArguments({scanId:this.scanId,networkId:r.authorization.scannerNetworkId,image:this.catalog.zap.reference,directory:r.directory,proxy:r.proxy,hostname:r.authorization.hostname,ip:r.authorization.ip}));
    r.scannerId=created.objectId||created.stdout.trim();if(!/^[a-f0-9]{64}$/.test(r.scannerId))throw fail('ACTIVE_SCANNER_IDENTITY_BLOCKED');
    await this.verify(session,r.authorization);
    const stop=()=>{(async()=>{
      const observed=(await this.adapter.inspect([r.scannerId],'container')).normalized;
      if(observed.objectId!==r.scannerId||observed.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}`||observed.labels?.['cloudsentinel.role']!=='active-zap')throw fail('ACTIVE_CLEANUP_OWNERSHIP');
      await this.adapter.run(['stop','--time','1',r.scannerId]);
    })().catch(()=>{});};
    signal?.addEventListener('abort',stop,{once:true});
    try {
      const sites=[];
      for(let i=0;i<plans.length;i++) {
        if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
        await this.verify(session,r.authorization);
        const proxy=new URL(r.proxy);
        const out=await this.adapter.run(['exec',r.scannerId,'zap.sh',`-Xmx${STORAGE.javaHeapMiB}m`,'-cmd','-host','127.0.0.1','-port','8090','-config','api.disablekey=false','-config',`api.key=${r.apiKey}`,'-dir','/home/zap/.ZAP','-config',`connection.proxyChain.enabled=true`,'-config',`connection.proxyChain.hostName=${proxy.hostname}`,'-config','connection.proxyChain.port=3128','-autorun',`/zap/wrk/plan-${i}.yaml`]);
        const initializationFailure=startupFailure(out.stdout,out.stderr);
        if(initializationFailure)throw fail(initializationFailure);
        if(out.exitCode!==0 || Buffer.byteLength(out.stdout||'')>1048576)throw fail('ACTIVE_SCAN_INCOMPLETE');
        const report=await this.adapter.run(['exec',r.scannerId,'cat',`/tmp/report-${i}.json`]);
        if(report.exitCode!==0||report.stderr!==''||Buffer.byteLength(report.stdout)>2097152)throw fail('ACTIVE_REPORT_INVALID');
        const parsed=JSON.parse(report.stdout);if(!Array.isArray(parsed.site))throw fail('ACTIVE_REPORT_INVALID');sites.push(...parsed.site);
        await this.verify(session,r.authorization);
      }
      return {completed:true,exitCode:0,report:{site:sites}};
    } finally {signal?.removeEventListener('abort',stop);}
  }
  async cleanup(session=this.pending) {
    const r=sessions.get(session);if(!r)return {cleaned:true,residual:[]};const residual=[];
    if(r.scannerId)try {
      const scanner=(await this.adapter.inspect([r.scannerId],'container')).normalized;
      if(scanner.objectId!==r.scannerId||scanner.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scanId}`||scanner.labels?.['cloudsentinel.role']!=='active-zap')throw fail('ACTIVE_CLEANUP_OWNERSHIP');
      await this.adapter.run(['stop',r.scannerId]);await this.adapter.run(['rm',r.scannerId]);r.scannerId=null;
    } catch(error){if(error.code==='MISSING_RESOURCE')r.scannerId=null;else residual.push({type:'active-zap',id:r.scannerId,error:error.code||'CLEANUP_FAILED'});}
    if(!r.scannerId) {
      const result=await this.lifecycle.cleanup(this.scanId);residual.push(...(result.residual||[]));
      if(r.directory)try {
        const s=await fs.lstat(r.directory),id=r.directoryIdentity;
        if(s.isSymbolicLink()||s.ino!==id.ino||s.dev!==id.dev||s.uid!==id.uid)throw fail('ACTIVE_CLEANUP_OWNERSHIP');
        for(const name of await fs.readdir(r.directory)){if(!r.files.has(name))throw fail('ACTIVE_CLEANUP_OWNERSHIP');const f=path.join(r.directory,name);if((await fs.lstat(f)).isSymbolicLink()||hash(await fs.readFile(f))!==r.files.get(name))throw fail('ACTIVE_CLEANUP_OWNERSHIP');await fs.unlink(f);r.files.delete(name);}
        await fs.rmdir(r.directory);r.directory=null;
      }catch(error){residual.push({type:'active-artifact',error:error.code||'CLEANUP_FAILED'});}
    }
    if(!residual.length){sessions.delete(session);this.pending=null;}
    return {cleaned:!residual.length,residual};
  }
}
module.exports={ActiveZapRuntime,capabilities,proxyPolicy,runArguments};
