'use strict';
const fs=require('fs/promises'),jwt=require('jsonwebtoken');const permits=new WeakMap();
const fail=()=>Object.assign(Error('ACTIVE_DIAGNOSTIC_AUTHORIZATION_REQUIRED'),{code:'ACTIVE_DIAGNOSTIC_AUTHORIZATION_REQUIRED'});
async function issue({pool,sessionFile,secret,input}){
 if(process.env.DAST_ACTIVE_ENABLED!=='false'||input.projectId!==11||!input.activeDiagnostic||input.passiveAutorun||input.scope!=='zap-python-containment'||!/^[a-z0-9][a-z0-9-]{0,29}$/.test(input.scanId||'')||!Number.isSafeInteger(input.executionId)||input.executionId<1||!Number.isSafeInteger(input.expiresAt)||input.expiresAt<=Date.now()||input.expiresAt>Date.now()+600000)throw fail();
 const parent=await fs.lstat(require('path').dirname(sessionFile));if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==process.getuid()||(parent.mode&511)!==448)throw fail();
 const h=await fs.open(sessionFile,require('fs').constants.O_RDONLY|require('fs').constants.O_NOFOLLOW);let session;
 try{const s=await h.stat();if(!s.isFile()||s.uid!==process.getuid()||(s.mode&511)!==384||s.size>16384)throw fail();session=JSON.parse(await h.readFile('utf8'));}finally{await h.close();}
 const u=jwt.verify(session.token,secret,{algorithms:['HS256']});if(u.id!==3||u.pipelineOrchestrator)throw fail();
 if((await pool.query('SELECT id FROM projects WHERE id=$1 AND user_id=$2',[11,3])).rows.length!==1)throw fail();
 // A local, permanent one-use claim. No production grant, enrollment or DB write.
 const claim=sessionFile+'.active-'+input.scanId+'.claimed';const f=await fs.open(claim,'wx',0o600);try{await f.writeFile(JSON.stringify({projectId:11,userId:3,scanId:input.scanId,expiresAt:input.expiresAt}));}finally{await f.close();}
 const permit=Object.freeze({});permits.set(permit,{scanId:input.scanId,executionId:input.executionId,expiresAt:input.expiresAt,used:false});return permit;
}
function valid(input){const p=permits.get(input.activePermit);return !!p&&!p.used&&p.scanId===input.scanId&&p.executionId===input.executionId&&p.expiresAt===input.expiresAt&&p.expiresAt>Date.now()&&input.projectId===11;}
function consume(input){if(!valid(input))throw fail();permits.get(input.activePermit).used=true;}
module.exports={issue,valid,consume};
