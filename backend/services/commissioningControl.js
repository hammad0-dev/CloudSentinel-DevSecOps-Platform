'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
function read(context,now=Date.now()){
 const file=process.env.DAST_COMMISSIONING_CONTROL_FILE,key=process.env.DAST_COMMISSIONING_CONTROL_KEY;
 if(!file||!path.isAbsolute(file)||!/^[a-f0-9]{64}$/.test(key||''))return null;
 let fd;
 try{
  const parent=fs.lstatSync(path.dirname(file));if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==process.getuid()||(parent.mode&0o777)!==0o700)return null;
  fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const stat=fs.fstatSync(fd);
  if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o600||stat.size>4096)return null;
  const {scope,mac}=JSON.parse(fs.readFileSync(fd,'utf8'));
  const legacy=process.env.NODE_ENV!=='production'&&Object.keys(scope||{}).sort().join(',')==='activeEnabled,executionId,expiresAt,phase,projectId,userId';
  const leased=Object.keys(scope||{}).sort().join(',')==='activeEnabled,executionId,expiresAt,leaseId,phase,projectId,userId'&&/^[0-9a-f-]{36}$/.test(scope?.leaseId||'');
  if(!scope||(!legacy&&!leased)||scope.activeEnabled!==true||scope.phase!=='ACTIVE_COMMISSIONING'||
     !['projectId','executionId','userId'].every(k=>scope[k]===context[k])||scope.projectId===17||!Number.isSafeInteger(scope.expiresAt)||scope.expiresAt<=now||scope.expiresAt>now+300000||!/^[a-f0-9]{64}$/.test(mac||''))return null;
  const expected=crypto.createHmac('sha256',Buffer.from(key,'hex')).update(JSON.stringify(scope)).digest();
  return crypto.timingSafeEqual(expected,Buffer.from(mac,'hex'))?scope:null;
 }catch(_){return null;}finally{if(fd!==undefined)fs.closeSync(fd);}
}
module.exports={read};
