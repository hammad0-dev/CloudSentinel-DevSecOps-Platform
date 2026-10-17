'use strict';
const fs=require('fs/promises'),os=require('os'),path=require('path'),crypto=require('crypto'),{isIP}=require('net');
const ID=/^[a-f0-9]{64}$/i,PART=/^[a-z0-9][a-z0-9_.-]{0,62}$/i;
const MAX_LOG=8192,MAX_FILE=65536;
const code=v=>typeof v==='string'&&/^[A-Z][A-Z0-9_]{0,63}$/.test(v)?v:'UNCLASSIFIED';
const safe=v=>typeof v==='string'&&/^[a-z0-9_.-]{1,128}$/i.test(v)?v:null;
const ip=v=>typeof v==='string'&&isIP(v)===4?v:null;
function redact(text,secrets=[]){
 let value=String(text);
 for(const secret of [...secrets].filter(x=>typeof x==='string'&&x.length>=4).sort((a,b)=>b.length-a.length))value=value.split(secret).join('[REDACTED]');
 return value.replace(/\b(?:Bearer|Basic)\s+[^\s]+/gi,'[REDACTED]')
  .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+:[^\s/@]+@/gi,'$1[REDACTED]@')
  .replace(/^\s*(?:[<>]\s*)?(?:authorization|proxy-authorization|cookie|set-cookie|authentication-info|proxy-authentication-info|www-authenticate|proxy-authenticate|referer|location|x-[\w-]+)\s*:[^\r\n]*/gim,'[REDACTED HEADER]')
  .replace(/(["'](?:password|token|secret|api[_-]?key|authorization|cookie)["']\s*:\s*)["'][^"'\r\n]*["']/gi,'$1"[REDACTED]"')
  .replace(/\b(?:[A-Za-z_][A-Za-z0-9_]*\s*=|password\s*:|token\s*:|secret\s*:|api[_-]?key\s*:|authorization\s*:|cookie\s*:)[^\r\n]*/gi,'[REDACTED VALUE]')
  .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g,'');
}
function log(value,secrets){
 if(typeof value!=='string')return {category:'MISSING',text:null};
 // Redact before truncating so a secret crossing the boundary cannot leak.
 const cleaned=Buffer.from(redact(value,secrets));let text=cleaned.subarray(0,MAX_LOG).toString('utf8');
 while(Buffer.byteLength(text)>MAX_LOG)text=text.slice(0,-1);
 return {category:value.length?'TEXT':'EMPTY',bytes:Buffer.byteLength(value),sha256:crypto.createHash('sha256').update(value).digest('hex'),truncated:cleaned.length>MAX_LOG,text};
}
async function save({adapter,resources={},projectId,executionId,scanId,error},{fsImpl=fs,baseDir=os.tmpdir(),secrets}={}){
 if(![projectId,executionId,scanId].every(v=>PART.test(String(v))))throw Object.assign(Error('invalid evidence identity'),{code:'INVALID_DIAGNOSTIC'});
 secrets=secrets||Object.entries(process.env).filter(([k])=>/TOKEN|SECRET|PASS|KEY|AUTH|COOKIE|CREDENTIAL|DATABASE_URL/i.test(k)).map(([,v])=>v);
 const id=ID.test(resources.gatewayId||'')?resources.gatewayId:null;
 const expected=resources.gatewayBinding||{};
 const record={schemaVersion:1,projectId,executionId,scanId,capturedAt:new Date().toISOString(),failureCode:code(error?.code),
  expected:{containerId:id,owner:safe(resources.owner),networkId:ID.test(expected.networkId||'')?expected.networkId:null,networkName:safe(expected.networkName),ip:ip(expected.ip),port:3128},
  inspection:{status:'NOT_CREATED'},logs:{status:'NOT_CREATED'},
  observation:error?.gatewayDiagnostic?{gatewayRunning:error.gatewayDiagnostic.gatewayRunning===true,expectedProxyIp:ip(error.gatewayDiagnostic.expectedProxyIp),inspectedGatewayIp:ip(error.gatewayDiagnostic.inspectedGatewayIp),proxyMatches:error.gatewayDiagnostic.proxyMatches===true}:null};
 if(id){
  try{
   const n=(await adapter.inspect([id],'container')).normalized;
   const owned=n.objectId===id&&n.labels?.['cloudsentinel.owner']===resources.owner&&n.labels?.['cloudsentinel.scan']===String(scanId)&&n.labels?.['cloudsentinel.role']==='gateway';
   const refs=resources.owned?.networks||[];
   if(refs.length>2)throw Error('invalid evidence network bounds');
   record.inspection={status:'OBSERVED',containerId:ID.test(n.objectId||'')?n.objectId:null,owner:safe(n.labels?.['cloudsentinel.owner']),scan:safe(n.labels?.['cloudsentinel.scan']),role:safe(n.labels?.['cloudsentinel.role']),ownershipMatches:owned,
    running:n.state?.Running===true,exitCode:Number.isInteger(n.state?.ExitCode)?n.state.ExitCode:null,oomKilled:n.state?.OOMKilled===true,
    networks:refs.map(ref=>{const e=n.networks?.[ref.name];return {name:safe(ref.name),expectedId:ID.test(ref.id||'')?ref.id:null,observedId:ID.test(e?.NetworkID||'')?e.NetworkID:null,ip:ip(e?.IPAddress)};})};
   if(owned){
    try{const r=await adapter.run(['logs','--tail','200',id]);record.logs={status:r.exitCode===0?'COLLECTED':'COMMAND_FAILED',exitCode:Number.isInteger(r.exitCode)?r.exitCode:null,stdout:log(r.stdout,secrets),stderr:log(r.stderr,secrets)};}
    catch(e){const native=require('./dockerAdapter').commandOutput(e);record.logs={status:'UNAVAILABLE',errorCode:code(e.code),exitCode:Number.isInteger(e.exitCode)?e.exitCode:null,stdout:log(native?.stdout,secrets),stderr:log(native?.stderr,secrets)};}
   }else record.logs={status:'OWNERSHIP_UNVERIFIED'};
   record.networkInspections=[];
   for(const ref of refs){
    if(!ID.test(ref.id||'')){record.networkInspections.push({status:'INVALID_REFERENCE'});continue;}
    try{
     const network=(await adapter.inspect([ref.id],'network')).normalized;
     record.networkInspections.push({status:'OBSERVED',expectedId:ref.id,observedId:ID.test(network.objectId||'')?network.objectId:null,
      identityMatches:network.objectId===ref.id&&network.name===ref.name,
      expectedOwner:safe(ref.labels?.['cloudsentinel.owner']),observedOwner:safe(network.labels?.['cloudsentinel.owner']),
      lifecycleId:safe(network.labels?.['cloudsentinel.lifecycle']),scan:safe(network.labels?.['cloudsentinel.scan']),role:safe(network.labels?.['cloudsentinel.role'])});
    }catch(e){record.networkInspections.push({status:'UNAVAILABLE',expectedId:ref.id,errorCode:code(e.code)});}
   }
  }catch(e){record.inspection={status:'UNAVAILABLE',errorCode:code(e.code)};record.logs={status:'INSPECTION_UNAVAILABLE'};}
 }
 let directory;
 try{
  directory=await fsImpl.mkdtemp(path.join(baseDir,`cloudsentinel-gateway-p${projectId}-e${executionId}-${scanId}-`));await fsImpl.chmod(directory,0o700);
  const stat=await fsImpl.lstat(directory);if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o700)throw Error('unsafe evidence directory');
  const file=path.join(directory,'gateway.json'),payload=JSON.stringify(record,null,2)+'\n';if(Buffer.byteLength(payload)>MAX_FILE)throw Error('evidence limit');
  const handle=await fsImpl.open(file,require('fs').constants.O_WRONLY|require('fs').constants.O_CREAT|require('fs').constants.O_EXCL|require('fs').constants.O_NOFOLLOW,0o600);
  try{await handle.chmod(0o600);await handle.writeFile(payload);}finally{await handle.close();}
  return file;
 }catch(_){
  // Do not recursively remove a path that may have been substituted. A failed
  // private artifact can remain for diagnosis; container cleanup still runs.
  throw Object.assign(Error('gateway evidence persistence failed'),{code:'GATEWAY_EVIDENCE_WRITE_FAILED'});
 }
}
module.exports={save,redact,MAX_LOG,MAX_FILE};
