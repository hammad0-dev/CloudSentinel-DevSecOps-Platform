'use strict';
const fs=require('fs/promises'),path=require('path'),os=require('os'),crypto=require('crypto');
async function save({authorization,diagnosticScope,scannerId,gatewayId,proxy,index,diagnostic,access,secrets=[]},{baseDir=os.tmpdir(),fsImpl=fs}={}){
 const a=authorization||diagnosticScope;
 if(authorization&&diagnosticScope||!a||![a.projectId,a.executionId,...(authorization?[a.userId]:[])].every(n=>Number.isSafeInteger(n)&&n>0)||a.projectId===17||!authorization&&diagnosticScope?.scope!=='zap-python-containment'||![0,1].includes(index)||!diagnostic)throw Error('INVALID_RESPONSE_EVIDENCE');
 const redact=require('./gatewayFailureEvidence').redact;
 const environmentSecrets=Object.entries(process.env).filter(([k])=>/TOKEN|SECRET|PASS|KEY|AUTH|COOKIE|CREDENTIAL/i.test(k)).map(([,v])=>v);
 const text=typeof access?.stdout==='string'?access.stdout:null;
 const record={projectId:a.projectId,executionId:a.executionId,...(authorization?{userId:a.userId}:{diagnosticOnly:true,productionReady:false}),index,capturedAt:new Date().toISOString(),
  scannerId:/^[a-f0-9]{64}$/.test(scannerId||'')?scannerId:null,gatewayId:/^[a-f0-9]{64}$/.test(gatewayId||'')?gatewayId:null,
  proxy:/^http:\/\/172\.30\.\d+\.\d+:3128$/.test(proxy||'')?proxy:null,diagnostic,
  accessLog:{status:text===null?'UNAVAILABLE':access.exitCode===0&&!access.stderr?'COLLECTED':'INCOMPLETE',exitCode:Number.isInteger(access?.exitCode)?access.exitCode:null,
   bytes:text===null?null:Buffer.byteLength(text),sha256:text===null?null:crypto.createHash('sha256').update(text).digest('hex'),
   excerpt:text===null?null:redact(text,[...secrets,...environmentSecrets]).slice(0,8192),truncated:text!==null&&text.length>8192}};
 const payload=JSON.stringify(record,null,2);if(Buffer.byteLength(payload)>32768)throw Error('RESPONSE_EVIDENCE_LIMIT');
 const directory=await fsImpl.mkdtemp(path.join(baseDir,`cs-response-p${a.projectId}-e${a.executionId}-`));await fsImpl.chmod(directory,0o700);
 const s=await fsImpl.lstat(directory);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o777)!==0o700)throw Error('PRIVATE_EVIDENCE_REQUIRED');
 const file=path.join(directory,'response.json'),h=await fsImpl.open(file,require('fs').constants.O_WRONLY|require('fs').constants.O_CREAT|require('fs').constants.O_EXCL|require('fs').constants.O_NOFOLLOW,0o600);
 try{await h.chmod(0o600);await h.writeFile(payload);}finally{await h.close();}
 return file;
}
module.exports={save};
