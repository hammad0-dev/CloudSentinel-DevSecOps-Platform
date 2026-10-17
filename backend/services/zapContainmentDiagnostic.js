'use strict';
// Private server/CLI diagnostic, deliberately separate from scan/grant execution.
const fs=require('fs/promises'),os=require('os'),path=require('path'),crypto=require('crypto');
const artifacts=require('../config/zap-containment-diagnostic.json');
const {isRuntimeAdapter}=require('./dockerAdapter');
const {SecureGatewayLifecycle,IMAGE:SQUID}=require('./dastGateway');
const {RuntimeObservation,runtimeReady}=require('./runtimeObservation');
const fixture=require('./dastFixture'),client=require('./dastAcceptanceClient');
const {inspectOwnedNetwork,verifyMemberships}=require('./ownedDockerNetworks');
const {runArguments,ActiveZapRuntime}=require('./activeZapRuntime');
const init=require('./zapInitialization'),writable=require('../config/zap-writable-paths.json');
const startup=require('./zapStartupEvidence');
const responsePermits=new WeakSet();
const passivePermits=new WeakMap();
function verifyPassivePlanPermit(permit,input){
 const p=permit&&passivePermits.get(permit);
 if(!p||!p.claimed||!isScope(p.scope,p.scope.scanId)||!(p.scope.passiveAutorun||p.scope.activeDiagnostic)||scopeParents.get(p.scope)!==input.scannerId||p.scannerId!==input.scannerId||p.gatewayId!==input.gatewayId||input.index!==0||crypto.createHash('sha256').update(JSON.stringify(input.args)).digest('hex')!==p.argsHash)throw fail('DIAGNOSTIC_ACTION_FORBIDDEN');
 return p.scope;
}
function claimPassivePlanPermit(permit,input){
 const p=permit&&passivePermits.get(permit);if(!p||p.claimed)throw fail('DIAGNOSTIC_ACTION_FORBIDDEN');p.claimed=true;return verifyPassivePlanPermit(permit,input);
}
function passivePlan(origin){
 const plan=require('./dastActiveScanner').commissioningPlan(origin,{baseline:true}).replace('reportDir: /zap/wrk','reportDir: /tmp').replace('reportFile: report.json','reportFile: report-0.json');
 const types=[...plan.matchAll(/^  - type: ([\w-]+)$/gm)].map(m=>m[1]);
 if(JSON.stringify(types)!==JSON.stringify(['requestor','passiveScan-wait','report'])||Buffer.byteLength(plan)>65536)throw fail('DIAGNOSTIC_PASSIVE_PLAN_BLOCKED');
 return plan;
}
function activeDiagnosticPlan(origin){
 const plan=require('./dastActiveScanner').commissioningPlan(origin).replace('reportDir: /zap/wrk','reportDir: /tmp').replace('reportFile: report.json','reportFile: report-0.json');
 const types=[...plan.matchAll(/^  - type: ([\w-]+)$/gm)].map(m=>m[1]);
 if(JSON.stringify(types)!==JSON.stringify(['activeScan-policy','requestor','activeScan','report'])||Buffer.byteLength(plan)>65536)throw fail('DIAGNOSTIC_ACTIVE_PLAN_BLOCKED');
 return plan;
}
function assertPassivePlan(plan,origin){if(typeof plan!=='string'||plan!==passivePlan(origin))throw fail('DIAGNOSTIC_PASSIVE_PLAN_BLOCKED');return true;}
const scopes=new WeakSet(),activeScopes=new WeakSet(),scopeParents=new WeakMap(),scopeSignals=new WeakMap(),used=new Set();
const normalizeVersion=v=>{if(!/^(0|[1-9]\d*)(\.(0|[1-9]\d*)){0,2}$/.test(String(v)))return null;return String(v).split('.').concat('0','0').slice(0,3).join('.');};
const fail=code=>Object.assign(new Error(code),{code,nonRetryable:true});
function isScope(scope,scanId){return scopes.has(scope)&&activeScopes.has(scope)&&scope.scanId===scanId&&scope.expiresAt>Date.now()&&!scopeSignals.get(scope)?.aborted&&process.env.DAST_ACTIVE_ENABLED==='false';}
function isNamespaceScope(scope,scanId,parentId){return isScope(scope,scanId)&&scopeParents.get(scope)===parentId;}
function validate(input,now=Date.now()){
  if(process.env.DAST_ACTIVE_ENABLED!=='false'||!input||input.scope!=='zap-python-containment'||!/^[a-z0-9][a-z0-9-]{0,29}$/.test(input.scanId||'')||![input.projectId,input.executionId].every(n=>Number.isSafeInteger(n)&&n>0)||input.projectId===17||!Number.isSafeInteger(input.expiresAt)||input.expiresAt<=now||input.expiresAt>now+600000||Object.keys(input).some(k=>!['scope','scanId','projectId','executionId','expiresAt','commissioningResponse','passiveAutorun','activeDiagnostic','activePermit'].includes(k)))throw fail('INVALID_DIAGNOSTIC_SCOPE');
  if(input.commissioningResponse!==undefined&&typeof input.commissioningResponse!=='boolean')throw fail('INVALID_DIAGNOSTIC_SCOPE');
  if(input.passiveAutorun!==undefined&&typeof input.passiveAutorun!=='boolean')throw fail('INVALID_DIAGNOSTIC_SCOPE');
  if(input.activeDiagnostic!==undefined&&typeof input.activeDiagnostic!=='boolean')throw fail('INVALID_DIAGNOSTIC_SCOPE');
  if(input.activeDiagnostic&&(!require('./activeDiagnosticAuthorization').valid(input)||input.passiveAutorun))throw fail('ACTIVE_DIAGNOSTIC_AUTHORIZATION_REQUIRED');
  if(input.activePermit&&!input.activeDiagnostic)throw fail('INVALID_DIAGNOSTIC_SCOPE');
  return Object.freeze({...input});
}
function verifyZapImage(raw){
  if(artifacts.scope!=='NON_SCANNING_CONTAINMENT_ONLY'||artifacts.productionReady!==false)throw fail('INVALID_DIAGNOSTIC_ARTIFACT_SCOPE');
  if(raw?.Id!==artifacts.imageId||raw.Architecture!==artifacts.architecture||raw.Os!==artifacts.os||JSON.stringify(raw.RootFS?.Layers)!==JSON.stringify(artifacts.layers)||!require('util').isDeepStrictEqual(raw.Config,artifacts.config))throw fail('DIAGNOSTIC_IMAGE_MISMATCH');
  return true;
}
function daemonViews(version,addons,rules){
  if(version?.version!=='2.17.0')throw fail('DIAGNOSTIC_API_NOT_READY');
  if(!Array.isArray(addons?.installedAddons)||!Array.isArray(rules?.scanners))throw fail('DIAGNOSTIC_API_NOT_READY');
  for(const [id,expected] of Object.entries(init.expectedAddons)){
    const loaded=addons.installedAddons.filter(a=>a.id===id);
    if(loaded.length>1)throw fail('DIAGNOSTIC_ADDONS_AMBIGUOUS');
    if(loaded.length===1&&normalizeVersion(loaded[0].version)!==normalizeVersion(expected))throw fail('DIAGNOSTIC_ADDONS_MISMATCH');
    if(loaded.length!==1||loaded[0].installationStatus!=='INSTALLED')throw fail('DIAGNOSTIC_ADDONS_NOT_READY');
  }
  const ids=rules.scanners.map(r=>String(r.id));
  if(require('../config/zap-active-policy-v1.json').approvedPluginIds.some(id=>!ids.includes(id)))throw fail('DIAGNOSTIC_RULES_NOT_READY');
  return {version:version.version,loadedAddons:addons.installedAddons.map(a=>({id:String(a.id).slice(0,64),version:String(a.version).slice(0,32),installationStatus:String(a.installationStatus).slice(0,32)})),ruleIds:ids};
}
function listeners(text,family,protocol='tcp'){
  if(![4,6].includes(family)||!['tcp','udp'].includes(protocol))throw fail('LISTENERS_INCOMPLETE');
  if(typeof text!=='string'||Buffer.byteLength(text)>65536||!/^\s*sl\s+local_address\s+(?:rem_address|remote_address)\s+st\b/.test(text))throw fail('LISTENERS_INCOMPLETE');
  const values=[],width=family===4?8:32;
  for(const line of text.trim().split('\n').slice(1)){
    const fields=line.trim().split(/\s+/),pattern=new RegExp(`^[A-Fa-f0-9]{${width}}:[A-Fa-f0-9]{4}$`);
    if(fields.length<10||!/^\d+:$/.test(fields[0])||!pattern.test(fields[1])||!pattern.test(fields[2])||!/^0[1-9A-C]$/i.test(fields[3])||!/^\d+$/.test(fields[9]))throw fail('LISTENERS_INCOMPLETE');
    if(protocol==='tcp'&&fields[3]!=='0A')continue;
    const [address,port]=fields[1].split(':');
    const loopback=family===4?/^[a-f0-9]{6}7f$/i.test(address):address.toUpperCase()==='00000000000000000000000001000000'||/^0000000000000000FFFF0000[a-f0-9]{6}7F$/i.test(address);
    if(!loopback||parseInt(port,16)===0)throw fail('NON_LOOPBACK_LISTENER');
    values.push({protocol,family,rawAddress:address,port:parseInt(port,16),loopback:true});
  }
  return values;
}
class ZapContainmentDiagnostic {
  constructor({adapter,lifecycle,input,offline=false}={}){
    if(offline?process.env.NODE_ENV!=='test':!isRuntimeAdapter(adapter))throw fail('INVALID_DIAGNOSTIC_ADAPTER');
    if(!(lifecycle instanceof SecureGatewayLifecycle)||lifecycle.adapter!==adapter)throw fail('INVALID_DIAGNOSTIC_LIFECYCLE');
    this.scope=validate(input);if(this.scope.activeDiagnostic)require('./activeDiagnosticAuthorization').consume(this.scope);if(used.has(this.scope.scanId))throw fail('DIAGNOSTIC_IDENTITY_REUSED');used.add(this.scope.scanId);scopes.add(this.scope);
    this.adapter=adapter;this.lifecycle=lifecycle;this.offline=offline;this.attempted=false;this.zapId=null;this.helper=null;this.directory=null;this.parentAttempted=false;
    this.name='cs-zap-'+this.scope.scanId;this.key=crypto.randomBytes(32).toString('hex');
  }
  check(signal){if(signal?.aborted)throw fail('DIAGNOSTIC_CANCELLED');if(!isScope(this.scope,this.scope.scanId))throw fail('DIAGNOSTIC_EXPIRED');}
  async #command(args,signal){this.check(signal);const result=await this.adapter.run(args);this.check(signal);if(result.exitCode!==0||result.stderr!=='')throw fail('DIAGNOSTIC_COMMAND_FAILED');return result;}
  async #verifyZap(){
    const n=(await this.adapter.inspect([this.zapId],'container')).normalized;
    const r=this.lifecycle.resources.get(this.scope.scanId),scanner=r?.owned.networks.find(n=>n.role==='scanner');
    if(!scanner)throw fail('DIAGNOSTIC_NETWORK_MISMATCH');
    verifyMemberships(n,[await inspectOwnedNetwork(this.adapter,scanner)]);
    if(n.objectId!==this.zapId||n.imageId!==artifacts.imageId||n.imageDigest!==artifacts.imageId||n.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scope.scanId}`||n.labels?.['cloudsentinel.scan']!==this.scope.scanId||n.labels?.['cloudsentinel.role']!=='zap-containment-diagnostic'||n.state?.Running!==true||n.security.user!=='1000:1000'||!n.security.readOnly||n.security.privileged||n.security.capAdd.length||!n.security.capDrop.includes('ALL')||!n.security.securityOpt.includes('no-new-privileges:true')||n.mounts.length!==1||n.mounts[0].Source!==this.directory||n.mounts[0].Destination!=='/zap/wrk'||n.mounts[0].RW!==false)throw fail('DIAGNOSTIC_ZAP_IDENTITY');
    const out=await this.adapter.run(['inspect','--format','{{json .}}',this.zapId]),raw=JSON.parse(out.stdout),h=raw.HostConfig;
    if(out.exitCode!==0||out.stderr!==''||h.Memory!==1536*1048576||h.NanoCpus!==1000000000||h.PidsLimit!==128||h.NetworkMode!==scanner.id||h.PublishAllPorts||Object.keys(h.PortBindings||{}).length||Object.values(raw.NetworkSettings?.Ports||{}).some(Boolean)||h.Binds?.length||!require('util').isDeepStrictEqual(h.Tmpfs,{'/tmp':'rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=1777','/home/zap/.ZAP':init.homeTmpfs().split(':')[1],[writable.profilePath]:init.profileTmpfs().split(':')[1]})||h.Sysctls?.['net.ipv6.conf.all.disable_ipv6']!=='1'||h.Sysctls?.['net.ipv6.conf.default.disable_ipv6']!=='1')throw fail('DIAGNOSTIC_ZAP_SECURITY');
    const stat=await fs.lstat(this.directory);
    if(!stat.isDirectory()||stat.isSymbolicLink()||stat.ino!==this.directoryIdentity.ino||stat.dev!==this.directoryIdentity.dev||stat.uid!==process.getuid()||(stat.mode&511)!==448)throw fail('DIAGNOSTIC_ARTIFACT_MISMATCH');
    if(this.responseFiles)for(const [name,digest] of this.responseFiles){
      const file=path.join(this.directory,name),s=await fs.lstat(file);
      if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&511)!==256||s.size>65536||crypto.createHash('sha256').update(await fs.readFile(file)).digest('hex')!==digest)throw fail('DIAGNOSTIC_ARTIFACT_MISMATCH');
    }
    return n;
  }
  async #verifyInfrastructure(){
    const r=this.lifecycle.resources.get(this.scope.scanId);
    if(!r?.diagnosticOnly||r.target?.hostname!==`${this.scope.scanId}.test`||r.target?.port!==18080)throw fail('DIAGNOSTIC_TARGET_MISMATCH');
    const scanner=await inspectOwnedNetwork(this.adapter,r.owned.networks.find(n=>n.role==='scanner'));
    const gateway=(await this.adapter.inspect([r.gatewayId],'container')).normalized;
    const target={...r.target,proxy:`http://${gateway.networks[scanner.name]?.IPAddress}:3128`};
    // Reuse production's read-only identity/path-policy verification, never its
    // grant, provisioning or scan entry points.
    const verifier=new ActiveZapRuntime({adapter:this.adapter,lifecycle:this.lifecycle,scanId:this.scope.scanId,offline:this.offline});
    await verifier.verifyFixture({resources:r,authorization:{...target,fixtureContainerId:r.fixtureResource.id},scannerNetwork:scanner,proxy:target.proxy});
    if(gateway.security.user!==`${process.getuid()}:${process.getgid()}`||!gateway.security.readOnly||gateway.security.privileged||gateway.security.capAdd.length||!gateway.security.capDrop.includes('ALL')||!gateway.security.securityOpt.includes('no-new-privileges:true')||gateway.mounts.length!==1||gateway.mounts[0].Source!==r.staged.filePath||gateway.mounts[0].Destination!==r.staged.containerPath||gateway.mounts[0].RW!==false)throw fail('DIAGNOSTIC_GATEWAY_IDENTITY');
    const raw=JSON.parse((await this.adapter.run(['inspect','--format','{{json .}}',r.gatewayId])).stdout);
    if(raw.HostConfig?.Memory!==268435456||raw.HostConfig?.NanoCpus!==1000000000||raw.HostConfig?.PidsLimit!==64)throw fail('DIAGNOSTIC_GATEWAY_SECURITY');
    return target;
  }
  async #preflight(signal){
    this.check(signal);
    if(process.getuid()!==1000||process.getgid()!==1000)throw fail('DIAGNOSTIC_UID_UNSUPPORTED');
    // No import, pull, build, mutable image reference or arbitrary path override.
    const z=await this.#command(['image','inspect',artifacts.imageId],signal);const list=JSON.parse(z.stdout);if(!Array.isArray(list)||list.length!==1)throw fail('DIAGNOSTIC_IMAGE_MISMATCH');verifyZapImage(list[0]);
    await fixture.verifyPythonAvailable(this.adapter);
    for(const image of [SQUID,client.IMAGE]){
      const [repository,digest]=image.split('@'),pinned=repository.replace(/:[^/:]+$/,'')+'@'+digest;
      const observed=JSON.parse((await this.#command(['image','inspect',pinned],signal)).stdout);
      if(observed.length!==1||observed[0].Architecture!=='amd64'||observed[0].Os!=='linux'||!observed[0].RepoDigests?.includes(pinned))throw fail('DIAGNOSTIC_IMAGE_MISMATCH');
    }
    for(const name of [this.name,...['client','fixture','gateway'].map(role=>require('./acceptanceNames').containerName(this.scope.scanId,role))]){
      try{await this.adapter.inspect([name],'container');throw fail('DIAGNOSTIC_NAME_COLLISION');}
      catch(error){if(error.code!=='MISSING_RESOURCE')throw error;}
    }
  }
  async api(view,signal){
    const paths={version:'core/view/version',addons:'autoupdate/view/installedAddons',rules:'ascan/view/scanners'};
    if(!Object.hasOwn(paths,view))throw fail('DIAGNOSTIC_ACTION_FORBIDDEN');
    const code="import urllib.request,json,sys;r=urllib.request.Request('http://127.0.0.1:8090/JSON/'+sys.argv[1]+'/',headers={'X-ZAP-API-Key':sys.argv[2]});o=urllib.request.build_opener(urllib.request.ProxyHandler({}));print(o.open(r,timeout=1).read(65537).decode())";
    const result=await this.#command(['exec',this.zapId,'python3','-I','-c',code,paths[view],this.key],signal);
    if(Buffer.byteLength(result.stdout)>65536)throw fail('DIAGNOSTIC_API_INCOMPLETE');return JSON.parse(result.stdout);
  }
  async #startDaemon(signal){
    for(const args of [init.profileBootstrapArguments(),init.jvmBootstrapArguments()])await this.#command(['exec',this.zapId,...args],signal);
    const r=this.lifecycle.resources.get(this.scope.scanId),scanner=r.owned.networks.find(n=>n.role==='scanner'),gateway=(await this.adapter.inspect([r.gatewayId],'container')).normalized;
    const proxy=gateway.networks[scanner.name].IPAddress;
    const args=['exec','-d',this.zapId,'/bin/sh','-c',`zap.sh "$@" >/tmp/zap-diagnostic.log 2>&1; cs_zap_status=$?; printf '%s\\n' "$cs_zap_status" >/tmp/zap-diagnostic.exit; exit "$cs_zap_status"`,'zap-diagnostic','-silent','-daemon','-host','127.0.0.1','-port','8090','-dir','/home/zap/.ZAP','-config',writable.callbackBinding,'-config','api.disablekey=false','-config',`api.key=${this.key}`,'-config','autoupdate.checkOnStart=false','-config','autoupdate.downloadNewRelease=false','-config','autoupdate.installAddonUpdates=false','-config','connection.proxyChain.enabled=true','-config',`connection.proxyChain.hostName=${proxy}`,'-config','connection.proxyChain.port=3128'];
    await this.#command(args,signal);
    const until=Math.min(this.scope.expiresAt,Date.now()+180000);let ready,reason='DIAGNOSTIC_DAEMON_NOT_READY';
    while(Date.now()<until){
      this.check(signal);
      ready=null;
      try{ready=daemonViews(await this.api('version',signal),await this.api('addons',signal),await this.api('rules',signal));}
      catch(error){this.readinessFailure=/^DIAGNOSTIC_[A-Z_]+$/.test(error.code||'')?error.code:'DIAGNOSTIC_API_NOT_READY';if(['DIAGNOSTIC_CANCELLED','DIAGNOSTIC_EXPIRED','DIAGNOSTIC_ADDONS_AMBIGUOUS','DIAGNOSTIC_ADDONS_MISMATCH'].includes(error.code))throw error;reason=this.readinessFailure;}
      let logReady=false;
      try{await this.#startupLog(signal);logReady=true;}catch(error){if(error.code!=='MISSING_RESOURCE')throw error;}
      if(ready&&logReady){
        try{const positive=await this.#positiveInitialization(signal);return {...ready,...positive};}
        catch(error){if(error.code!=='DIAGNOSTIC_POSITIVE_INITIALIZATION_PENDING')throw error;this.readinessFailure=reason=error.code;}
      }
      await new Promise(resolve=>setTimeout(resolve,250));
    }
    this.readinessFailure=reason;throw fail('DIAGNOSTIC_INITIALIZATION_TIMEOUT');
  }
  async #startupLog(signal){
    this.check(signal);const evidence=await this.#captureStartup();this.check(signal);
      if(evidence.container?.running===false)throw fail('DIAGNOSTIC_CONTAINER_EXITED');
      if(evidence.container?.oomKilled)throw fail('DIAGNOSTIC_CONTAINER_OOM');
      if(evidence.captureError)throw fail('DIAGNOSTIC_STARTUP_EVIDENCE_MISSING');
    if(evidence.daemonExitCode!==null&&evidence.daemonExitCode!==undefined)throw fail('DIAGNOSTIC_DAEMON_EXITED');
    if(evidence.log?.sampled)throw fail('DIAGNOSTIC_STARTUP_LOG_INCOMPLETE');
    if(evidence.logBytes===null||evidence.logBytes===0)throw fail('MISSING_RESOURCE');
    if(evidence.log?.classification)throw fail('DIAGNOSTIC_INITIALIZATION_FAILED');
  }
  async #positiveInitialization(signal){
    const out=await this.#command(['exec',this.zapId,...startup.READINESS_ARGS],signal);
    if(Buffer.byteLength(out.stdout)>524288)throw fail('DIAGNOSTIC_STARTUP_EVIDENCE_MISSING');
    const v=JSON.parse(out.stdout),log=this.startupEvidence?.log;
    if(!log?.extensionsLoaded||!log?.loopbackReady||!Array.isArray(v.writable)||v.writable.length!==4||v.writable.some(x=>x!==true)||v.policy?.xmlParsed!==true||!Number.isSafeInteger(v.policy.bytes)||v.policy.bytes<1||v.policy.bytes>65536||!/^[a-f0-9]{64}$/.test(v.policy.sha256||''))throw fail('DIAGNOSTIC_POSITIVE_INITIALIZATION_PENDING');
    const observed=[];
    for(const [name,family,protocol] of [['tcp',4,'tcp'],['tcp6',6,'tcp'],['udp',4,'udp'],['udp6',6,'udp']])observed.push(...listeners(v.tables?.[name],family,protocol));
    if(!observed.some(n=>n.protocol==='tcp'&&n.port===8090))throw fail('DIAGNOSTIC_POSITIVE_INITIALIZATION_PENDING');
    return {policy:v.policy,writablePathsVerified:true,listeners:observed};
  }
  async #captureStartup(){
    const evidence={readinessCheck:this.readinessFailure||null};
    try{
      const inspected=await this.adapter.run(['inspect','--format','{{json .}}',this.zapId]);
      const raw=JSON.parse(inspected.stdout),labels=raw.Config?.Labels;
      if(raw.Id!==this.zapId||raw.Image!==artifacts.imageId||labels?.['cloudsentinel.scan']!==this.scope.scanId||labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scope.scanId}`||labels?.['cloudsentinel.role']!=='zap-containment-diagnostic')throw fail('DIAGNOSTIC_ZAP_IDENTITY');
      const s=raw.State||{};evidence.container={running:s.Running===true,exitCode:Number.isInteger(s.ExitCode)?s.ExitCode:null,oomKilled:s.OOMKilled===true,error:startup.sanitize(s.Error,[this.key]).slice(0,512)};
      if(s.Running!==true){evidence.captureError='CONTAINER_NOT_RUNNING';return this.startupEvidence=evidence;}
      const out=await this.adapter.run(['exec',this.zapId,'python3','-I','-c',startup.PROBE]);
      if(out.exitCode!==0||out.stderr||Buffer.byteLength(out.stdout)>2097152)throw fail('DIAGNOSTIC_STARTUP_EVIDENCE_MISSING');
      const v=JSON.parse(out.stdout);
      if(typeof v.log!=='string'||!(v.logBytes===null||Number.isSafeInteger(v.logBytes)&&v.logBytes>=0)||!(v.daemonExitCode===null||Number.isInteger(v.daemonExitCode)&&v.daemonExitCode>=0&&v.daemonExitCode<=255))throw fail('DIAGNOSTIC_STARTUP_EVIDENCE_MISSING');
      evidence.commandExitCode=out.exitCode;evidence.logBytes=v.logBytes;evidence.daemonExitCode=v.daemonExitCode;evidence.log=startup.summarize(v.log,[this.key]);evidence.log.sampled=v.logBytes>1048576;
    }catch(error){evidence.captureError=/^[A-Z_]{1,64}$/.test(error.code||'')?error.code:'STARTUP_CAPTURE_FAILED';evidence.commandExitCode=Number.isInteger(error.exitCode)?error.exitCode:null;}
    return this.startupEvidence=evidence;
  }
  async #benignResponses(target,signal){
    const expected={'/test/sqli':'[["demo-one"]]','/test/xss':'<html><body>fixture: hello</body></html>'},results=[];
    for(const [pathname,body] of Object.entries(expected)){
      this.check(signal);const args=client.buildProbeCommand('http',target,{path:pathname,proxy:target.proxy});args[args.indexOf('--output')+1]='-';args[args.indexOf('--write-out')+1]='|CS_ZPD|%{http_code} %{http_connect} %{remote_ip}';
      const out=await client.execute(this.adapter,this.helper,args);this.check(signal);
      const parts=out.stdout.trimEnd().split('|CS_ZPD|'),observed=parts[0],status=parts.length===2?parts[1]:null;
      if(out.exitCode!==0||Buffer.byteLength(out.stdout)>8192||Buffer.byteLength(out.stderr)>8192||status!==`200 000 ${new URL(target.proxy).hostname}`||observed!==body||/Location:|ERR_|timed? out|refused/i.test(out.stderr))throw fail('DIAGNOSTIC_FIXTURE_RESPONSE_MISMATCH');
      results.push({path:pathname,status:200,body:observed,proxyPeer:new URL(target.proxy).hostname,exploitPayload:false});
    }
    return results;
  }
  async #commissioningResponses(target,signal,permit){
    if(!responsePermits.has(permit)||!(this.scope.commissioningResponse||this.scope.passiveAutorun||this.scope.activeDiagnostic))throw fail('DIAGNOSTIC_ACTION_FORBIDDEN');
    responsePermits.delete(permit); // One use; never a production authorization.
    const traffic=require('./zapCommissioningTraffic'),r=this.lifecycle.resources.get(this.scope.scanId);
    this.responseFiles=new Map();await traffic.stage(this.directory,this.responseFiles);
    const nonce=crypto.randomBytes(16).toString('hex'),results=[];
    const parent=await this.#verifyZap(),scanner=r.owned.networks.find(n=>n.role==='scanner'),clientIp=parent.networks[scanner.name]?.IPAddress;
    if(!/^172\.30\.\d+\.\d+$/.test(clientIp||''))throw fail('DIAGNOSTIC_NETWORK_MISMATCH');
    let failure,access;
    try{
      for(let index=0;index<2;index++){
        this.check(signal);await this.#verifyInfrastructure();await this.#verifyZap();
        const route=index===0?'sqli?id=1':'xss?q=hello';
        const request=`GET http://${target.hostname}:18080/test/${route}&cs_commission=${nonce}-${index} HTTP/1.1\r\nHost: ${target.hostname}:18080\r\nConnection: close\r\n\r\n`;
        const out=await this.#command(traffic.command(this.zapId,'request',{key:this.key,request}),signal);
        if(Buffer.byteLength(out.stdout)>65536)throw fail('DIAGNOSTIC_API_INCOMPLETE');
        const value=JSON.parse(out.stdout);
        try{traffic.response(value,request,index===0?'[["demo-one"]]':'<html><body>fixture: hello</body></html>');}
        catch(error){error.responseIndex=index;throw error;}
        const m=value.sendRequest[0];results.push({index,path:'/test/'+route.split('?')[0],status:200,requestSha256:crypto.createHash('sha256').update(m.requestHeader).digest('hex'),headerSha256:crypto.createHash('sha256').update(m.responseHeader).digest('hex'),bodySha256:crypto.createHash('sha256').update(m.responseBody).digest('hex')});
      }
    }catch(error){failure=error;}
    try{access=await this.adapter.run(['exec',r.gatewayId,'cat','/tmp/cloudsentinel-active-access.log']);}catch(_){access=null;}
    if(!failure)try{if(access?.exitCode!==0||access.stderr)throw fail('COMMISSIONING_PROXY_LOG_BLOCKED');traffic.correlate(access.stdout,{nonce,clientIp,hostname:target.hostname});}catch(error){failure=error;}
    const diagnostic=failure?.responseDiagnostic||{results,failedPredicates:failure?[failure.code||'DIAGNOSTIC_RESPONSE_FAILED']:[]};
    try{
      this.responseEvidenceFile=await require('./commissioningResponseEvidence').save({diagnosticScope:this.scope,scannerId:this.zapId,gatewayId:r.gatewayId,proxy:target.proxy,index:failure?.responseIndex||0,diagnostic,access,secrets:[this.key]});
    }catch(_){if(!failure)failure=fail('DIAGNOSTIC_RESPONSE_EVIDENCE_WRITE_FAILED');else failure.responseEvidenceError='DIAGNOSTIC_RESPONSE_EVIDENCE_WRITE_FAILED';}
    if(failure)throw failure;
    this.check(signal);await this.#verifyInfrastructure();await this.#verifyZap();
    return {verified:true,diagnosticOnly:true,productionReady:false,zapOriginated:true,results,evidenceFile:this.responseEvidenceFile};
  }
  async #passiveAutorun(target,signal){
    if(!(this.scope.passiveAutorun||this.scope.activeDiagnostic))throw fail('DIAGNOSTIC_ACTION_FORBIDDEN');
    const active=this.scope.activeDiagnostic===true;
    const traffic=require('./zapCommissioningTraffic'),origin=`http://${target.hostname}:18080`,plan=active?activeDiagnosticPlan(origin):passivePlan(origin),r=this.lifecycle.resources.get(this.scope.scanId);
    if(!active)assertPassivePlan(plan,origin);this.check(signal);await this.#verifyInfrastructure();await this.#verifyZap();
    const file='plan-0.yaml';await fs.writeFile(path.join(this.directory,file),plan,{flag:'wx',mode:0o400});this.responseFiles.set(file,crypto.createHash('sha256').update(plan).digest('hex'));
    const configure=JSON.parse((await this.#command(traffic.command(this.zapId,'configure',{key:this.key,hostname:target.hostname}),signal)).stdout);
    if(configure.rateConfigured!==2||configure.concurrencyConfigured!==1)throw fail('DIAGNOSTIC_PASSIVE_CONFIGURATION_BLOCKED');
    const stopped=JSON.parse((await this.#command(traffic.command(this.zapId,'stop',{key:this.key}),signal)).stdout);
    if(stopped.Result!=='OK')throw fail('DIAGNOSTIC_DAEMON_STOP_BLOCKED');
    const until=Math.min(this.scope.expiresAt,Date.now()+10000);let exited=false;
    while(Date.now()<until){this.check(signal);const state=await this.#captureStartup();if(state.daemonExitCode===0){exited=true;break;}if(state.daemonExitCode!==null&&state.daemonExitCode!==undefined)throw fail('DIAGNOSTIC_DAEMON_STOP_BLOCKED');await new Promise(resolve=>setTimeout(resolve,250));}
    if(!exited)throw fail('DIAGNOSTIC_DAEMON_STOP_BLOCKED');
    // executePlan invokes zap.sh itself, matching ActiveZapRuntime's slice(3)
    // contract: forward options only, never a second executable/file argument.
    const proxy=new URL(target.proxy),args=['-cmd','-host','127.0.0.1','-port','8090','-config',writable.callbackBinding,'-config','api.disablekey=false','-config',`api.key=${this.key}`,'-dir','/home/zap/.ZAP','-config','connection.proxyChain.enabled=true','-config',`connection.proxyChain.hostName=${proxy.hostname}`,'-config','connection.proxyChain.port=3128','-autorun','/zap/wrk/plan-0.yaml'];
    const permit=Object.freeze({});passivePermits.set(permit,{scope:this.scope,claimed:false,scannerId:this.zapId,gatewayId:r.gatewayId,argsHash:crypto.createHash('sha256').update(JSON.stringify(args)).digest('hex')});
    const verify=async()=>{this.check(signal);await this.#verifyInfrastructure();await this.#verifyZap();};
    let out;const controller=new AbortController(),abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});const bound=active?setTimeout(abort,Math.max(0,this.scope.expiresAt-Date.now()-30000)):null;
    const started=Date.now();
    try{out=await traffic.executePlan({adapter:this.adapter,scannerId:this.zapId,gatewayId:r.gatewayId,index:0,args,diagnosticPermit:permit,verify,signal:active?controller.signal:signal});}
    catch(error){this.automationEvidenceFile=error.automationEvidenceFile;if(error.automationEvidenceError)this.automationEvidenceError=error.automationEvidenceError;throw error;}
    finally{if(bound)clearTimeout(bound);signal?.removeEventListener('abort',abort);passivePermits.delete(permit);}
    // Persist native output before classification and before any cleanup.
    this.automationEvidenceFile=await require('./zapAutomationEvidence').save({diagnosticScope:this.scope,scannerId:this.zapId,index:0,output:out,reason:'DIAGNOSTIC_PASSIVE_COMMAND_OUTPUT',secrets:[this.key]});
    out.diagnosticBudget?.check();
    const report=await (out.diagnosticBudget?out.diagnosticBudget.run(()=>this.#command(['exec',this.zapId,'cat','/tmp/report-0.json'],signal)):this.#command(['exec',this.zapId,'cat','/tmp/report-0.json'],signal));
    if(active){
      let parsedReport=null;try{parsedReport=JSON.parse(report.stdout);}catch(_){}
      const access=await this.#command(['exec',r.gatewayId,'cat','/tmp/cloudsentinel-active-access.log'],signal);
      const inspected=(await this.adapter.inspect([this.zapId],'container')).normalized;const clientIp=Object.values(inspected.networks||{}).map(n=>n.IPAddress).find(ip=>require('net').isIP(ip)===4);
      const requests=require('./activeDastEvidence').requests(access.stdout,{clientIp,hostname:target.hostname});
      this.activeEvidence=await require('./activeDastEvidence').save({diagnosticOnly:true,projectId:this.scope.projectId,executionId:this.scope.executionId,requests,artifacts:{automation:out,report:report.stdout,alerts:parsedReport?.site?.flatMap(s=>s.alerts||[])||null,requests,identity:{diagnosticId:this.scope.scanId,diagnosticOnly:true,productionReady:false,scannerId:this.zapId,gatewayId:r.gatewayId,fixtureId:r.fixtureResource.id,zapImage:artifacts.imageId,fixtureImage:require('./activeRuntimeArtifacts').artifacts.fixture.imageId,approvedRules:require('./dastActiveScanner').POLICY.approvedPluginIds,durationMs:Date.now()-started}}},{secrets:[this.key]});
    }
    out.diagnosticBudget?.complete();
    const failure=init.startupFailure(out.stdout,out.stderr);if(failure)throw fail(failure);
    if(out.exitCode!==0)throw fail('DIAGNOSTIC_PASSIVE_INCOMPLETE');
    if(Buffer.byteLength(report.stdout)>2097152)throw fail('DIAGNOSTIC_PASSIVE_REPORT_INVALID');
    const parsed=JSON.parse(report.stdout);if(!Array.isArray(parsed.site)||parsed.site.length<1)throw fail('DIAGNOSTIC_PASSIVE_REPORT_INVALID');
    // Validate every site and finding against the fixture, without production
    // authorizations, persistence, grants, or normalization into Active findings.
    for(const site of parsed.site){if(site['@name']!==origin)throw fail('DIAGNOSTIC_PASSIVE_REPORT_OUT_OF_SCOPE');}
    const findings=require('./dastBaselineScanner').extractFindings(parsed);
    for(const finding of findings){const url=new URL(finding.endpoint);if(url.origin!==origin||!['/test/sqli','/test/xss'].includes(url.pathname)||url.username||url.password||url.hash)throw fail('DIAGNOSTIC_PASSIVE_REPORT_OUT_OF_SCOPE');}
    const byCwe={};if(active)for(const site of parsed.site)for(const alert of site.alerts||[]){if(require('./dastActiveScanner').POLICY.approvedPluginIds.map(String).includes(String(alert.pluginid))&&/^[0-9]+$/.test(String(alert.cweid)))byCwe[String(alert.cweid)]=(byCwe[String(alert.cweid)]||0)+(alert.instances?.length||1);}
    if(out.diagnosticBudget)await out.diagnosticBudget.run(verify);else await verify();out.diagnosticBudget?.complete();return {completed:true,exitCode:out.exitCode,diagnosticOnly:true,productionReady:false,activeScanJobs:active?1:0,...(active?{findingsByCwe:byCwe,retainedEvidence:this.activeEvidence,durationMs:Date.now()-started}:{}),reportSha256:crypto.createHash('sha256').update(report.stdout).digest('hex'),siteCount:parsed.site.length,findingCount:findings.length,evidenceFile:this.automationEvidenceFile,configuredRequestsPerSecond:2,configuredConcurrency:1,rateEnforcement:'UNVERIFIED'};
  }
  async run(options={}){
    if(!options||typeof options!=='object'||Object.keys(options).some(k=>k!=='signal')||(options.signal!==undefined&&!(options.signal instanceof AbortSignal)))throw fail('INVALID_DIAGNOSTIC_SCOPE');
    const {signal}=options;
    if(this.attempted)throw fail('DIAGNOSTIC_ALREADY_ATTEMPTED');this.attempted=true;activeScopes.add(this.scope);scopeSignals.set(this.scope,signal);
    let result={status:'BLOCKED',stage:'PREFLIGHT',diagnosticOnly:true,fullContainment:false,containmentReady:false,zapApplicationRequests:false,scope:this.scope},failure;
    try{
      await this.#preflight(signal);this.check(signal);
      const input={...this.scope,fixtureKind:fixture.PYTHON_KIND,nativeConnect:true,mode:'full',diagnosticScope:this.scope,target:{hostname:`${this.scope.scanId}.test`,port:18080}};
      result.stage='INFRASTRUCTURE';this.infrastructureAttempted=true;await this.lifecycle.provision(input);this.check(signal);
      const r=this.lifecycle.resources.get(this.scope.scanId),scanner=r.owned.networks.find(n=>n.role==='scanner'),target=await this.#verifyInfrastructure();
      this.directory=await fs.mkdtemp(path.join(os.tmpdir(),'cs-zap-diagnostic-'));await fs.chmod(this.directory,448);this.directoryIdentity=await fs.lstat(this.directory);
      const args=runArguments({scanId:this.scope.scanId,networkId:scanner.id,image:artifacts.imageId,directory:this.directory,proxy:target.proxy,hostname:target.hostname,ip:target.ip});args[args.indexOf('cloudsentinel.role=active-zap')]='cloudsentinel.role=zap-containment-diagnostic';args.splice(args.indexOf(artifacts.imageId),0,'--no-healthcheck');
      result.stage='ZAP_PROVISION';this.parentAttempted=true;const created=await this.#command(args,signal);const zapId=created.objectId||created.stdout.trim();if(!/^[a-f0-9]{64}$/.test(zapId))throw fail('DIAGNOSTIC_ZAP_IDENTITY');this.zapId=zapId;
      await this.#verifyZap();scopeParents.set(this.scope,this.zapId);result.stage='DAEMON_INITIALIZATION';result.initialization=await this.#startDaemon(signal);await this.#verifyZap();
      result.stage='HELPER_PROVISION';this.helperAttempted=true;this.helper=await client.provision(this.adapter,{scanId:this.scope.scanId,networkId:scanner.id,networkReference:scanner,nativeArtifact:r.nativeArtifact,namespaceParent:this.zapId,diagnosticScope:this.scope,onCreated:h=>{this.helper=h;r.clientResource=h;}});
      r.clientResource=this.helper;this.lifecycle.observation.bindAcceptanceClient(client,this.helper);
      result.namespaceBeforeProbes=(await client.verifyClient(this.adapter,this.helper)).namespaceEvidence;
      result.stage='NAMESPACE_PROBES';
      const e=await this.lifecycle.observation.collectActiveFixture({projectId:this.scope.projectId,executionId:this.scope.executionId,scanId:this.scope.scanId,gatewayContainerId:r.gatewayId,scannerContainerId:this.helper.id,fixtureContainerId:r.fixtureResource.id,scannerNetworkId:scanner.id,fixtureNetworkId:r.fixtureResource.networkId,networkReferences:r.owned.networks,target,stagedPolicy:r.staged,nativeConnect:true,mode:'full'});
      if(e.namespaceScope!=='ZAP_SHARED_NETWORK_NAMESPACE'||e.namespaceEvidence?.zapContainerId!==this.zapId||!e.namespaceEvidence.equivalent||(!this.offline&&!runtimeReady(e)))throw fail('DIAGNOSTIC_NAMESPACE_UNVERIFIED');
      this.check(signal);await this.#verifyZap();result.stage='BENIGN_RESPONSES';const responses=await this.#benignResponses(target,signal);result.stage='LISTENERS';
      const observedListeners=[];
      for(const [name,family,protocol] of [['tcp',4,'tcp'],['tcp6',6,'tcp'],['udp',4,'udp'],['udp6',6,'udp']]){
        const native=await client.execute(this.adapter,this.helper,['cat',`/proc/net/${name}`]);
        if(native.exitCode!==0||native.stderr!=='')throw fail('LISTENERS_INCOMPLETE');
        observedListeners.push(...listeners(native.stdout,family,protocol));
      }
      if(!observedListeners.some(n=>n.protocol==='tcp'&&n.port===8090))throw fail('API_LISTENER_MISSING');
      const after=(await client.verifyClient(this.adapter,this.helper)).namespaceEvidence;if(JSON.stringify(after)!==JSON.stringify(e.namespaceEvidence))throw fail('DIAGNOSTIC_NAMESPACE_UNVERIFIED');
      if(this.scope.passiveAutorun){const pscan=result.initialization.loadedAddons.filter(a=>a.id==='pscan');if(pscan.length!==1||normalizeVersion(pscan[0].version)!=='0.6.0'||pscan[0].installationStatus!=='INSTALLED')throw fail('DIAGNOSTIC_PASSIVE_ADDON_BLOCKED');}
      if(this.scope.commissioningResponse||this.scope.passiveAutorun||this.scope.activeDiagnostic){result.stage='COMMISSIONING_RESPONSES';const permit=Object.freeze({});responsePermits.add(permit);result.commissioningResponse=await this.#commissioningResponses(target,signal,permit);result.zapApplicationRequests=true;}
      if(this.scope.passiveAutorun||this.scope.activeDiagnostic){result.stage=this.scope.activeDiagnostic?'ACTIVE_DIAGNOSTIC':'PASSIVE_AUTORUN';const output=await this.#passiveAutorun(target,signal);if(this.scope.activeDiagnostic)result.activeAutomation=output;else result.passiveAutomation=output;}
      this.check(signal);if(!(this.scope.passiveAutorun||this.scope.activeDiagnostic))await this.#startupLog(signal);await this.#verifyInfrastructure();result={...result,status:'PASS',stage:'PROBES_COMPLETE',verification:this.offline?'MOCK_ONLY_NOT_VERIFIED':'RUNTIME_OBSERVED',namespaceEvidence:e.namespaceEvidence,probes:e.probes,responses,routes:e.routes,listeners:observedListeners,resources:{zapId:this.zapId,helperId:this.helper.id,fixtureId:r.fixtureResource.id,gatewayId:r.gatewayId,networkIds:r.owned.networks.map(n=>n.id)},limitations:['Shared namespace probes are emitted by the helper, not the ZAP application.','IPv6 is verified route/address/listener absence, not a packet-level test.','Redirect path and destination policy are tested; an actual cross-origin redirect chain is not emitted by the current Python fixture.',this.scope.activeDiagnostic?'Only this diagnostic job completion is observed; measured rate enforcement and production acceptance remain UNVERIFIED.':'No Active job completion, cancellation or rate enforcement is established.']};
    }catch(error){
      const original=error;
      if(signal?.aborted)error=fail('DIAGNOSTIC_CANCELLED');else if(this.scope.expiresAt<=Date.now())error=fail('DIAGNOSTIC_EXPIRED');failure=error;result.reason=/^[A-Z_]{1,64}$/.test(error.code||'')?error.code:'DIAGNOSTIC_FAILED';
      if(result.stage==='DAEMON_INITIALIZATION')result.initializationFailure={check:result.reason,commandExitCode:Number.isInteger(original.exitCode)?original.exitCode:null,timedOut:original.timedOut===true,commandError:startup.sanitize(original.commandStderr||'', [this.key]).slice(0,1024)};
      if(original.namespaceDiagnostic)result.namespaceDiagnostic=original.namespaceDiagnostic;
      if(original.responseDiagnostic)result.responseDiagnostic=original.responseDiagnostic;
      if(original.responseEvidenceError)result.responseEvidenceError=original.responseEvidenceError;
      if(original.networkDiagnostic)result.networkDiagnostic=original.networkDiagnostic;
      if(original.probes)result.probes=original.probes.map(p=>({name:p.name,sourceId:p.sourceId,actual:p.actual,expected:p.expected,complete:p.complete,exitCode:p.exitCode,evidenceType:p.evidenceType,nativeEvidence:p.nativeEvidence,httpStatus:p.httpStatus,connectStatus:p.connectStatus}));
      const tcp=require('./tcpDiagnostic').diagnostic(original.probe);if(tcp)result.tcpDiagnostic=tcp;
      if(original.diagnosticFile)result.probeDiagnosticFile=original.diagnosticFile;
    }
    finally{
      if(this.zapId){const previous=this.startupEvidence;result.startupEvidence=await this.#captureStartup();if(previous?.log?.classification)result.startupFailureEvidence=previous;}
      const r=this.lifecycle.resources.get(this.scope.scanId);
      result.resources=result.resources||{zapId:this.zapId,helperId:this.helper?.id||null,fixtureId:r?.fixtureResource?.id||null,gatewayId:r?.gatewayId||null,networkIds:r?.owned?.networks?.map(n=>n.id)||[]};
      if(this.responseEvidenceFile)result.responseEvidenceFile=this.responseEvidenceFile;
      if(this.scope.activeDiagnostic&&!this.activeEvidence){
        try{this.activeEvidence=await require('./activeDastEvidence').save({diagnosticOnly:true,projectId:this.scope.projectId,executionId:this.scope.executionId,artifacts:{automation:this.automationEvidenceFile?JSON.parse(await fs.readFile(this.automationEvidenceFile,'utf8')):null,identity:{diagnosticId:this.scope.scanId,diagnosticOnly:true,productionReady:false,reason:result.reason||'INCOMPLETE',scannerId:this.zapId,fixtureId:r?.fixtureResource?.id,gatewayId:r?.gatewayId}}},{secrets:[this.key]});}
        catch(_){result.status='FAIL';result.reason=result.reason||'DIAGNOSTIC_EVIDENCE_WRITE_FAILED';}
      }
      if(this.activeEvidence)result.activeEvidence=this.activeEvidence;
      if(this.automationEvidenceFile)result.automationEvidenceFile=this.automationEvidenceFile;
      if(this.automationEvidenceError)result.automationEvidenceError=this.automationEvidenceError;
      result.validationStatus=result.status;
      result.cleanup=await this.cleanup();if(!result.cleanup.cleaned){if(result.reason)result.validationReason=result.reason;result.status='FAIL';result.reason='DIAGNOSTIC_CLEANUP_FAILED';}
    }
    result.exitCode=result.status==='PASS'?0:failure?.code==='DIAGNOSTIC_CANCELLED'?2:1;return result;
  }
  async cleanup(){
    activeScopes.delete(this.scope);
    const residual=[];
    if(!this.helper&&this.helperAttempted)try{
      const n=(await this.adapter.inspect([require('./acceptanceNames').containerName(this.scope.scanId,'client')],'container')).normalized;
      if(n.imageDigest!==client.IMAGE||n.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scope.scanId}`||n.labels?.['cloudsentinel.role']!=='acceptance-client'||n.security.networkMode!==`container:${this.zapId}`)throw fail('CLEANUP_OWNERSHIP_MISMATCH');
      this.helper={id:n.objectId,owner:`cloudsentinel-${this.scope.scanId}`};
    }catch(error){if(error.code!=='MISSING_RESOURCE')return {cleaned:false,residual:[{type:'namespace-helper',code:'UNCERTAIN_CREATE'}]};}
    if(this.helper)try{const out=await client.cleanup(this.adapter,this.helper);if(!out.cleaned)throw fail('HELPER_CLEANUP_FAILED');this.helper=null;const r=this.lifecycle.resources.get(this.scope.scanId);if(r)delete r.clientResource;}catch(error){residual.push({type:'namespace-helper',code:error.code||'CLEANUP_FAILED'});}
    if(this.helper)return {cleaned:false,residual};
    if(!this.zapId&&this.parentAttempted)try{this.zapId=(await this.adapter.inspect([this.name],'container')).normalized.objectId;}catch(error){if(error.code!=='MISSING_RESOURCE')residual.push({type:'zap',code:'UNCERTAIN_CREATE'});}
    if(this.zapId)try{const n=(await this.adapter.inspect([this.zapId],'container')).normalized;if(n.objectId!==this.zapId||n.imageId!==artifacts.imageId||n.imageDigest!==artifacts.imageId||n.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scope.scanId}`||n.labels?.['cloudsentinel.scan']!==this.scope.scanId||n.labels?.['cloudsentinel.role']!=='zap-containment-diagnostic')throw fail('CLEANUP_OWNERSHIP_MISMATCH');await this.adapter.run(['stop',this.zapId]);await this.adapter.run(['rm',this.zapId]);this.zapId=null;}catch(error){if(error.code==='MISSING_RESOURCE')this.zapId=null;else residual.push({type:'zap',code:error.code||'CLEANUP_FAILED'});}
    if(!this.zapId){try{
      const r=this.lifecycle.resources.get(this.scope.scanId);
      if(r&&this.infrastructureAttempted)for(const role of ['fixture','gateway']){
        if(role==='fixture'?r.fixtureResource?.id:r.gatewayId)continue;
        try{
          const n=(await this.adapter.inspect([require('./acceptanceNames').containerName(this.scope.scanId,role)],'container')).normalized;
          if(n.labels?.['cloudsentinel.owner']!==`cloudsentinel-${this.scope.scanId}`||n.labels?.['cloudsentinel.role']!==role||(role==='fixture'?n.imageId!==fixture.pythonArtifact().imageId:n.imageDigest!==SQUID))throw fail('CLEANUP_OWNERSHIP_MISMATCH');
          if(role==='gateway'){r.gatewayId=n.objectId;r.owner=`cloudsentinel-${this.scope.scanId}`;}
          else r.fixtureResource={id:n.objectId,owner:`cloudsentinel-${this.scope.scanId}`,scanId:this.scope.scanId,fixtureKind:fixture.PYTHON_KIND,imageId:n.imageId};
        }catch(error){if(error.code!=='MISSING_RESOURCE')throw error;}
      }
      const out=await this.lifecycle.cleanup(this.scope.scanId);residual.push(...(out.residual||[]));
      if(out.state!=='CLEANED'||this.lifecycle.resources.has(this.scope.scanId)||!Array.isArray(out.residual))throw fail('LIFECYCLE_CLEANUP_UNVERIFIED');
    }catch(error){residual.push({type:'lifecycle',code:error.code||'CLEANUP_FAILED'});}
      if(this.directory)try{const s=await fs.lstat(this.directory);if(s.isSymbolicLink()||s.ino!==this.directoryIdentity.ino||s.dev!==this.directoryIdentity.dev||s.uid!==this.directoryIdentity.uid)throw fail('CLEANUP_OWNERSHIP_MISMATCH');
        if(this.responseFiles)for(const [name,digest] of this.responseFiles){const file=path.join(this.directory,name),st=await fs.lstat(file);if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||st.size>65536||crypto.createHash('sha256').update(await fs.readFile(file)).digest('hex')!==digest)throw fail('CLEANUP_OWNERSHIP_MISMATCH');await fs.unlink(file);}
        await fs.rmdir(this.directory);this.directory=null;}catch(error){residual.push({type:'artifact',code:error.code||'CLEANUP_FAILED'});}}
    return {cleaned:!residual.length,residual};
  }
}
module.exports={activeDiagnosticPlan,ZapContainmentDiagnostic,isScope,isNamespaceScope,validate,verifyZapImage,listeners,daemonViews,passivePlan,assertPassivePlan,claimPassivePlanPermit,verifyPassivePlanPermit};
