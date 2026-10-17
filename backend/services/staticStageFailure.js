'use strict';
const fs=require('fs'),os=require('os'),path=require('path');
function sanitize(value,env=process.env){
 let text=typeof value==='string'?value:'Static stage failed';
 for(const [key,secret] of Object.entries(env)) if(/TOKEN|SECRET|PASS|KEY|AUTH|COOKIE|CREDENTIAL|DATABASE_URL/i.test(key)&&typeof secret==='string'&&secret.length>=4)text=text.split(secret).join('[REDACTED]');
 return text.replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi,'$1[REDACTED]@').replace(/\b(Bearer|Basic)\s+[^\s]+/gi,'[REDACTED]').replace(/\b(password|token|secret|api[_-]?key|authorization|cookie)\s*[:=]\s*[^\s,;]+/gi,'$1=[REDACTED]').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g,'').slice(0,4000);
}
function responseError(error){return sanitize(typeof error?.response?.data?.error==='string'?error.response.data.error:error?.message);}
function save(record,{baseDir=os.tmpdir(),fsImpl=fs}={}){
 const directory=fsImpl.mkdtempSync(path.join(baseDir,'cs-sast-failure-'));fsImpl.chmodSync(directory,0o700);
 const file=path.join(directory,'failure.json');const safe={projectId:record.projectId,scanId:record.scanId,executionId:record.executionId||null,capturedAt:new Date().toISOString(),message:sanitize(record.message)};
 fsImpl.writeFileSync(file,JSON.stringify(safe,null,2),{mode:0o600,flag:'wx'});return file;
}
module.exports={sanitize,responseError,save};
