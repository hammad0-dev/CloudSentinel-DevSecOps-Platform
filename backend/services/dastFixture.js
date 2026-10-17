"use strict";
const fs=require("fs/promises");
const path=require("path");
const os=require("os");
const crypto=require("crypto");
const IMAGE="nginx:1.27.5-alpine@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8";
const ID=/^[a-f0-9]{12,64}$/i;
const PYTHON_KIND='cloudsentinel-vulnerable-v1';
const PYTHON_TMPFS='/tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700';
function pythonArtifact() {
  const a=require('../config/active-runtime-artifacts.json').fixture;
  if(!a || a.fixtureKind!==PYTHON_KIND || !/^sha256:[a-f0-9]{64}$/.test(a.reference||'') || a.reference!==a.imageId || a.architecture!=='amd64' || a.os!=='linux' || !/^[a-f0-9]{64}$/.test(a.sourceSha256||'') || a.validation?.verified!==true || a.validation.scope!=='NETWORK_NONE_FIXTURE_ONLY')fail('ACTIVE_FIXTURE_BLOCKED','verified Python artifact required');
  return a;
}
function verifyPythonImage(raw,a=pythonArtifact()) {
  if(raw?.Id!==a.imageId || raw.Architecture!==a.architecture || raw.Os!==a.os || JSON.stringify(raw.RootFS?.Layers)!==JSON.stringify(a.layerDiffIds))fail('ACTIVE_IMAGE_MISMATCH','Python image identity mismatch');
  const canonical=value=>JSON.stringify(value,Object.keys(value).sort());
  const expected={...a.expectedConfig,Cmd:a.expectedConfig?.Cmd??null},actual={...raw.Config,Cmd:raw.Config?.Cmd??null};
  // Compare nested objects without depending on Docker's key ordering.
  const equal=(x,y)=>x===y || !!x&&!!y&&typeof x==='object'&&typeof y==='object'&&Array.isArray(x)===Array.isArray(y)&&canonical(Object.keys(x).sort())===canonical(Object.keys(y).sort())&&Object.keys(x).every(k=>equal(x[k],y[k]));
  if(!equal(expected,actual) || actual.User!=='10001:10001' || actual.Labels?.['cloudsentinel.fixture.source.sha256']!==a.sourceSha256)fail('ACTIVE_IMAGE_MISMATCH','Python image configuration mismatch');
  return a;
}
async function verifyPythonAvailable(adapter) {
  const a=pythonArtifact(),r=await adapter.run(['image','inspect',a.imageId]);
  if(r.exitCode!==0 || r.stderr!=='')fail('ACTIVE_IMAGE_MISMATCH','Python image unavailable');
  const values=JSON.parse(r.stdout);
  if(!Array.isArray(values)||values.length!==1)fail('ACTIVE_IMAGE_MISMATCH','ambiguous Python image');
  return verifyPythonImage(values[0],a);
}
function verifyPythonRuntime(raw,{id,owner,scanId,networkId},a=pythonArtifact(),ready=true) {
  const h=raw?.HostConfig||{},c=raw?.Config||{},n=raw?.NetworkSettings||{};
  if(JSON.stringify(c.Entrypoint)!==JSON.stringify(a.expectedConfig.Entrypoint)||c.WorkingDir!==a.expectedConfig.WorkingDir||JSON.stringify(c.Env)!==JSON.stringify(a.expectedConfig.Env))fail('ACTIVE_FIXTURE_IDENTITY_MISMATCH','Python runtime command/environment changed');
  if(raw?.Id!==id || raw.Image!==a.imageId || c.Image!==a.imageId || c.User!=='10001:10001' || c.Labels?.['cloudsentinel.owner']!==owner || c.Labels?.['cloudsentinel.scan']!==String(scanId) || c.Labels?.['cloudsentinel.role']!=='fixture' || !raw.State?.Running || (ready&&raw.State?.Health?.Status!=='healthy'))fail('ACTIVE_FIXTURE_IDENTITY_MISMATCH','Python fixture identity/readiness mismatch');
  if(h.NetworkMode!==networkId || !h.ReadonlyRootfs || h.Privileged!==false || JSON.stringify(h.CapDrop)!=='["ALL"]' || h.CapAdd?.length || !h.SecurityOpt?.includes('no-new-privileges:true') || h.SecurityOpt.includes('no-new-privileges:false') || h.Memory!==268435456 || h.NanoCpus!==1000000000 || h.PidsLimit!==64 || JSON.stringify(h.Tmpfs)!==JSON.stringify({'/tmp':PYTHON_TMPFS.slice(5)}) || h.Binds?.length || h.Mounts?.length || h.VolumesFrom?.length || Object.keys(h.PortBindings||{}).length || h.PublishAllPorts || Object.values(n.Ports||{}).some(Boolean) || (raw.Mounts||[]).some(m=>m.Type!=='tmpfs'||m.Destination!=='/tmp'||m.Source||m.RW!==true))fail('ACTIVE_FIXTURE_SECURITY_MISMATCH','Python fixture security mismatch');
  if(h.Sysctls?.['net.ipv6.conf.all.disable_ipv6']!=='1'||h.Sysctls?.['net.ipv6.conf.default.disable_ipv6']!=='1')fail('ACTIVE_FIXTURE_SECURITY_MISMATCH','IPv6 must be disabled');
  if(!Array.isArray(raw.Mounts)||raw.Mounts.length>1)fail('ACTIVE_FIXTURE_SECURITY_MISMATCH','unexpected or missing mount evidence');
  return true;
}
async function provisionPython(adapter,o) {
  o.check?.();
  if(o.projectId===17 || !Number.isSafeInteger(o.projectId)||o.projectId<1 || !Number.isSafeInteger(o.executionId)||o.executionId<1 || !/^[a-z0-9-]+\.test$/.test(o.host||'') || o.port!==18080 || !/^[a-f0-9]{64}$/.test(o.networkId||''))fail('ACTIVE_SCOPE_BLOCKED','execution-bound disposable fixture required');
  const name=require('./acceptanceNames').containerName(String(o.scanId),'fixture'),a=await verifyPythonAvailable(adapter),owner='cloudsentinel-'+o.scanId;
  const args=['run','-d','--pull=never','--name',name,'--network',o.networkId,'--network-alias',o.host,'--label','cloudsentinel.owner='+owner,'--label','cloudsentinel.scan='+o.scanId,'--label','cloudsentinel.role=fixture','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m','--cpus','1','--tmpfs',PYTHON_TMPFS,'--sysctl','net.ipv6.conf.all.disable_ipv6=1','--sysctl','net.ipv6.conf.default.disable_ipv6=1',a.imageId];
  o.check?.();
  const r=await adapter.run(args),id=r.objectId||r.stdout?.trim();
  if(!/^[a-f0-9]{64}$/.test(id||''))fail('IDENTITY_MISSING','Python fixture ID missing');
  const ref={id,owner,scanId:String(o.scanId),networkId:o.networkId,fixtureKind:PYTHON_KIND,imageId:a.imageId};o.onCreated?.(ref);
  let native;
  for(let attempt=0;attempt<20;attempt++) {
    o.check?.();
    const observed=await adapter.run(['inspect','--format','{{json .}}',id]);
    if(observed.exitCode!==0||observed.stderr!=='')fail('ACTIVE_FIXTURE_BLOCKED','Python inspection failed');
    native=JSON.parse(observed.stdout);verifyPythonRuntime(native,ref,a,false);
    if(native.State.Health?.Status==='healthy')break;
    if(native.State.Health?.Status==='unhealthy')fail('ACTIVE_FIXTURE_BLOCKED','Python fixture unhealthy');
    await new Promise(resolve=>setTimeout(resolve,500));
  }
  verifyPythonRuntime(native,ref,a);
  const net=(await adapter.inspect([o.networkId],'network')).normalized;
  require('./ownedDockerNetworks').verifyMemberships({networks:native.NetworkSettings.Networks},[net]);
  const ip=native.NetworkSettings.Networks[net.name].IPAddress;
  if(!verifyAssignedIp(ip,net))fail('IP_MISMATCH','Python IP outside owned network');
  if(!net.internal||net.ipv6||net.labels?.['cloudsentinel.scan']!==String(o.scanId)||net.labels?.['cloudsentinel.project']!==String(o.projectId)||net.labels?.['cloudsentinel.execution']!==String(o.executionId)||net.labels?.['cloudsentinel.role']!=='fixture'||!/^cloudsentinel-[a-f0-9]{12}$/.test(net.labels?.['cloudsentinel.owner']||''))fail('NETWORK_MISMATCH','Python network must be execution-owned/internal/IPv4');
  return {...ref,ip};
}
function fail(code,msg){const e=new Error(msg);e.code=code;throw e;}
function validate(o={}){if(!/^[a-z0-9.-]+$/i.test(String(o.host||""))||!Number.isInteger(o.port)||o.port<1||o.port>65535)fail("INVALID_CONFIG","invalid fixture host/port");if(!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(String(o.unauthorizedIp||"")))fail("INVALID_CONFIG","invalid unauthorized IP");return {host:String(o.host).toLowerCase(),port:o.port,unauthorizedHost:String(o.unauthorizedHost||"unauthorized.test"),unauthorizedIp:o.unauthorizedIp,metadataIp:"169.254.169.254",unauthorizedPort:Number(o.unauthorizedPort||portPlus(o.port))};}
function portPlus(p){return p===65535?1:p+1;}
function nginxConfig(o){const t=validate(o);return [
"worker_processes 1;","pid /tmp/nginx.pid;","error_log /dev/stderr;","events { worker_connections 32; }","http {","  access_log /dev/stdout;","  client_body_temp_path /tmp/client_body;","  proxy_temp_path /tmp/proxy;","  fastcgi_temp_path /tmp/fastcgi;","  uwsgi_temp_path /tmp/uwsgi;","  scgi_temp_path /tmp/scgi;","  server {","    listen "+t.port+";","    location = /health { return 200 'ok'; }","    location = /redirect/same { return 302 http://"+t.host+":"+t.port+"/health; }","    location = /redirect/host { return 302 http://"+t.unauthorizedHost+":"+t.port+"/health; }","    location = /redirect/ip { return 302 http://"+t.unauthorizedIp+":"+t.port+"/health; }","    location = /redirect/port { return 302 http://"+t.host+":"+t.unauthorizedPort+"/health; }","    location = /redirect/metadata { return 302 http://"+t.metadataIp+"/; }","  }","}",""
].join("\n");}
function stage(o){const t=validate(o);const bytes=nginxConfig(t);const digest="sha256:"+crypto.createHash("sha256").update(bytes).digest("hex");return Object.freeze({target:t,bytes,digest,containerPath:"/etc/nginx/nginx.conf",mount:{readOnly:true},ownership:{owned:true,scanId:String(o.scanId)}});}
async function stageOwned(o) {
  const base=path.resolve(String(o && o.baseDir || os.tmpdir()));
  const t=validate(o);
  const bytes=nginxConfig(t);
  const digest="sha256:"+crypto.createHash("sha256").update(bytes).digest("hex");
  const directory=await fs.mkdtemp(path.join(base,"cloudsentinel-nginx-"+String(o.scanId)+"-"));
  try {
    await fs.chmod(directory,0o700);
    const filePath=path.join(directory,"nginx.conf");
    await fs.writeFile(filePath,bytes,{encoding:"utf8",flag:"wx",mode:0o600});
    await fs.chmod(filePath,0o600);
    const artifact=Object.freeze({scanId:String(o.scanId),directory,filePath,bytes,digest,containerPath:"/etc/nginx/nginx.conf",mount:"type=bind,src="+filePath+",dst=/etc/nginx/nginx.conf,readonly",ownership:{owned:true,scanId:String(o.scanId)}});
    return artifact;
  } catch(e) { await fs.rm(directory,{recursive:true,force:true}); throw e; }
}
async function verifyArtifact(a) {
  if (!a || a.ownership?.owned!==true || !path.isAbsolute(a.filePath) || !path.isAbsolute(a.directory) || !a.filePath.startsWith(a.directory+path.sep)) fail("ARTIFACT_INVALID","invalid owned fixture artifact");
  const st=await fs.lstat(a.filePath); if (!st.isFile() || st.isSymbolicLink()) fail("ARTIFACT_INVALID","fixture artifact must be a regular file");
  const dir=await fs.lstat(a.directory);
  if (!dir.isDirectory() || dir.isSymbolicLink() || (dir.mode & 0o777)!==0o700 || (st.mode & 0o777)!==0o600 || st.uid!==process.getuid() || dir.uid!==process.getuid()) fail("ARTIFACT_INVALID","fixture artifact ownership or permissions mismatch");
  if (a.ownership.scanId!==a.scanId || a.containerPath!=="/etc/nginx/nginx.conf" || a.mount!==`type=bind,src=${a.filePath},dst=${a.containerPath},readonly` || /[,\r\n]/.test(a.filePath)) fail("ARTIFACT_INVALID","fixture mount or ownership mismatch");
  const bytes=await fs.readFile(a.filePath,"utf8"); const d="sha256:"+crypto.createHash("sha256").update(bytes).digest("hex");
  if (bytes!==a.bytes || d!==a.digest) fail("ARTIFACT_TAMPERED","fixture artifact digest mismatch");
  return a;
}
async function cleanupArtifact(a) {
  if (!a?.ownership?.owned || !a.directory || !a.filePath) fail("CLEANUP_UNOWNED","refusing unowned fixture artifact");
  await fs.rm(a.directory,{recursive:true,force:true});
  return {cleaned:true,residual:[]};
}

function ipNum(ip){const a=String(ip).split(".").map(Number);if(a.length!==4||a.some(x=>!Number.isInteger(x)||x<0||x>255))return null;return (((a[0]*256+a[1])*256+a[2])*256+a[3]);}
function verifyAssignedIp(ip,network){const n=ipNum(ip),sub=String(network?.subnet||"").split("/");const base=ipNum(sub[0]),bits=Number(sub[1]);if(n===null||base===null||bits<1||bits>30)return false;const size=2**(32-bits),mask=Math.floor(n/size)*size;if(mask!==Math.floor(base/size)*size)return false;const gateway=ipNum(network.gateway);return n!==mask&&n!==mask+size-1&&n!==gateway;}
async function provision(adapter,o){if(o?.fixtureKind===PYTHON_KIND)return provisionPython(adapter,o);if(o?.fixtureKind!==undefined)fail("ACTIVE_SCOPE_BLOCKED","unknown fixture kind");require('./acceptanceNames').containerName(String(o?.scanId),'fixture');if(!adapter||typeof adapter.run!=="function")fail("INVALID_ADAPTER","adapter required");const s=await stageOwned(o),owner="cloudsentinel-"+String(o.scanId);await verifyArtifact(s);o.onStaged?.(s); const args=["run","-d","--pull=never","--name",require('./acceptanceNames').containerName(String(o.scanId),'fixture'),"--network",String(o.networkId),"--network-alias",o.host,"--label","cloudsentinel.owner="+owner,"--label","cloudsentinel.role=fixture","--read-only","--sysctl","net.ipv6.conf.all.disable_ipv6=1","--sysctl","net.ipv6.conf.default.disable_ipv6=1","--user",`${process.getuid()}:${process.getgid()}`,"--tmpfs","/tmp:rw,noexec,nosuid,size=16m,mode=1777","--cap-drop","ALL","--security-opt","no-new-privileges:true","--mount",s.mount,"--entrypoint","/usr/sbin/nginx",IMAGE,"-g","daemon off;"];const r=await adapter.run(args);const id=r.objectId||String(r.stdout||"").trim();if(!ID.test(id))fail("IDENTITY_MISSING","fixture container ID missing");o.onCreated?.({id,staged:s,owner,networkId:String(o.networkId)});if(typeof adapter.inspect!=="function")fail("INSPECT_REQUIRED","adapter.inspect required");const obs=await adapter.inspect([id],"container");const n=obs.normalized||obs;if(n.objectId!==id||n.imageDigest!==IMAGE||n.labels?.["cloudsentinel.owner"]!==owner||n.labels?.["cloudsentinel.role"]!=="fixture")fail("IDENTITY_MISMATCH","fixture identity evidence mismatch");const mount=(n.mounts||[]).find(m=>m.Destination===s.containerPath);if(!mount||mount.Type!=="bind"||mount.Source!==s.filePath||mount.RW!==false)fail("MOUNT_MISMATCH","fixture configuration mount is not verified read-only");const entries=Object.entries(n.networks||{});if(entries.length!==1)fail("NETWORK_MISMATCH","fixture must have exactly one network");const ip=entries[0][1]?.IPAddress||entries[0][1]?.ipAddress;const netObs=await adapter.inspect([String(o.networkId)],"network");const net=netObs.normalized||netObs;if(entries[0][0]!==net.name||entries[0][1]?.NetworkID!==net.id||net.id!==String(o.networkId))fail("NETWORK_MISMATCH","fixture network name/ID mismatch");if(!verifyAssignedIp(ip,net))fail("IP_MISMATCH","fixture IPv4 is outside verified network or reserved");return {id,staged:s,owner,networkId:String(o.networkId),ip};}
async function cleanup(adapter,r){if(!r)return {cleaned:true,residual:[]};if(!r.id){if(r.staged)await cleanupArtifact(r.staged);return {cleaned:true,residual:[]};}const cur=await adapter.inspect([r.id],"container").catch(e=>{if(e.code==="MISSING_RESOURCE")return null;throw e;});if(!cur){if(r.staged)await cleanupArtifact(r.staged);return {cleaned:true,residual:[]};}const n=cur.normalized||cur;if(n.objectId!==r.id||n.labels?.["cloudsentinel.owner"]!==r.owner||n.labels?.["cloudsentinel.role"]!=="fixture")fail("OWNERSHIP_MISMATCH","refusing unowned cleanup");if(r.fixtureKind===PYTHON_KIND&&(n.imageId!==r.imageId||n.labels?.["cloudsentinel.scan"]!==r.scanId))fail("OWNERSHIP_MISMATCH","Python cleanup image/scan mismatch");const residual=[];for(const a of [["stop",r.id],["rm",r.id]]){try{await adapter.run(a);}catch(e){residual.push({id:r.id,operation:a[0],error:e.code||e.message});}}if (!residual.length && r.staged) { try { await cleanupArtifact(r.staged); } catch (e) { residual.push({type:"policy",error:e.code||e.message}); } } return {cleaned:residual.length===0,residual};}
module.exports={PYTHON_KIND,pythonArtifact,verifyPythonImage,verifyPythonAvailable,verifyPythonRuntime,provisionPython,IMAGE,validate,nginxConfig,stage,stageOwned,verifyArtifact,cleanupArtifact,provision,cleanup};
