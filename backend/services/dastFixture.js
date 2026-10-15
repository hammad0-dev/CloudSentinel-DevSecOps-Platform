"use strict";
const fs=require("fs/promises");
const path=require("path");
const os=require("os");
const crypto=require("crypto");
const IMAGE="nginx:1.27.5-alpine@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8";
const ID=/^[a-f0-9]{12,64}$/i;
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
async function provision(adapter,o){require('./acceptanceNames').containerName(String(o?.scanId),'fixture');if(!adapter||typeof adapter.run!=="function")fail("INVALID_ADAPTER","adapter required");const s=await stageOwned(o),owner="cloudsentinel-"+String(o.scanId);await verifyArtifact(s);o.onStaged?.(s); const args=["run","-d","--pull=never","--name",require('./acceptanceNames').containerName(String(o.scanId),'fixture'),"--network",String(o.networkId),"--network-alias",o.host,"--label","cloudsentinel.owner="+owner,"--label","cloudsentinel.role=fixture","--read-only","--sysctl","net.ipv6.conf.all.disable_ipv6=1","--sysctl","net.ipv6.conf.default.disable_ipv6=1","--user",`${process.getuid()}:${process.getgid()}`,"--tmpfs","/tmp:rw,noexec,nosuid,size=16m,mode=1777","--cap-drop","ALL","--security-opt","no-new-privileges:true","--mount",s.mount,"--entrypoint","/usr/sbin/nginx",IMAGE,"-g","daemon off;"];const r=await adapter.run(args);const id=r.objectId||String(r.stdout||"").trim();if(!ID.test(id))fail("IDENTITY_MISSING","fixture container ID missing");o.onCreated?.({id,staged:s,owner,networkId:String(o.networkId)});if(typeof adapter.inspect!=="function")fail("INSPECT_REQUIRED","adapter.inspect required");const obs=await adapter.inspect([id],"container");const n=obs.normalized||obs;if(n.objectId!==id||n.imageDigest!==IMAGE||n.labels?.["cloudsentinel.owner"]!==owner||n.labels?.["cloudsentinel.role"]!=="fixture")fail("IDENTITY_MISMATCH","fixture identity evidence mismatch");const mount=(n.mounts||[]).find(m=>m.Destination===s.containerPath);if(!mount||mount.Type!=="bind"||mount.Source!==s.filePath||mount.RW!==false)fail("MOUNT_MISMATCH","fixture configuration mount is not verified read-only");const entries=Object.entries(n.networks||{});if(entries.length!==1)fail("NETWORK_MISMATCH","fixture must have exactly one network");const ip=entries[0][1]?.IPAddress||entries[0][1]?.ipAddress;const netObs=await adapter.inspect([String(o.networkId)],"network");const net=netObs.normalized||netObs;if(entries[0][0]!==net.name||entries[0][1]?.NetworkID!==net.id||net.id!==String(o.networkId))fail("NETWORK_MISMATCH","fixture network name/ID mismatch");if(!verifyAssignedIp(ip,net))fail("IP_MISMATCH","fixture IPv4 is outside verified network or reserved");return {id,staged:s,owner,networkId:String(o.networkId),ip};}
async function cleanup(adapter,r){if(!r)return {cleaned:true,residual:[]};if(!r.id){if(r.staged)await cleanupArtifact(r.staged);return {cleaned:true,residual:[]};}const cur=await adapter.inspect([r.id],"container").catch(e=>{if(e.code==="MISSING_RESOURCE")return null;throw e;});if(!cur){if(r.staged)await cleanupArtifact(r.staged);return {cleaned:true,residual:[]};}const n=cur.normalized||cur;if(n.objectId!==r.id||n.labels?.["cloudsentinel.owner"]!==r.owner||n.labels?.["cloudsentinel.role"]!=="fixture")fail("OWNERSHIP_MISMATCH","refusing unowned cleanup");const residual=[];for(const a of [["stop",r.id],["rm",r.id]]){try{await adapter.run(a);}catch(e){residual.push({id:r.id,operation:a[0],error:e.code||e.message});}}if (!residual.length && r.staged) { try { await cleanupArtifact(r.staged); } catch (e) { residual.push({type:"policy",error:e.code||e.message}); } } return {cleaned:residual.length===0,residual};}
module.exports={IMAGE,validate,nginxConfig,stage,stageOwned,verifyArtifact,cleanupArtifact,provision,cleanup};
