'use strict';
// Private administrator CLI: verifies an existing normal-login session and
// ownership before issuing a random approval. Never signs a user session.
const fs=require('fs/promises'),crypto=require('crypto'),os=require('os'),path=require('path'),jwt=require('jsonwebtoken');
async function issue({pool,projectId,sessionFile,secret,authorized}){
 if(authorized!==true||!Number.isSafeInteger(projectId)||projectId<=0||projectId===17)throw Error('APPROVAL_ISSUANCE_BLOCKED');
 const handle=await fs.open(sessionFile,require('fs').constants.O_RDONLY|require('fs').constants.O_NOFOLLOW);
 let session;
 try{const stat=await handle.stat();if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o600||stat.size>16384)throw Error('PRIVATE_SESSION_REQUIRED');session=JSON.parse(await handle.readFile('utf8'));}finally{await handle.close();}
 const user=jwt.verify(session.token,secret,{algorithms:['HS256']});
 if(!Number.isSafeInteger(user.id)||user.id<=0||user.pipelineOrchestrator===true)throw Error('OWNER_SESSION_REQUIRED');
 const owner=await pool.query('SELECT u.id FROM users u JOIN projects p ON p.user_id=u.id WHERE u.id=$1 AND p.id=$2',[user.id,projectId]);
 if(owner.rows.length!==1)throw Error('PROJECT_OWNERSHIP_REQUIRED');
 const token=crypto.randomBytes(32).toString('hex'),expiresAt=Date.now()+600000;
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'cs-commissioning-approval-'));await fs.chmod(directory,0o700);
 await fs.writeFile(path.join(directory,'approval.json'),JSON.stringify({approval:token,sha256:crypto.createHash('sha256').update(token).digest('hex'),scope:{projectId,userId:user.id,expiresAt}},null,2),{mode:0o600,flag:'wx'});
 return {directory,projectId,userId:user.id,expiresAt}; // Never return the secret.
}
async function issueContinuation({pool,projectId,executionId,sessionFile,secret,key,controlFile,authorized}){
 const started=require('perf_hooks').performance.now();
 if(authorized!==true||!Number.isSafeInteger(projectId)||projectId<=0||projectId===17||!Number.isSafeInteger(executionId)||executionId<=0||!/^[a-f0-9]{64}$/.test(key||'')||!path.isAbsolute(controlFile||''))throw Error('CONTINUATION_BLOCKED');
 const parent=await fs.lstat(path.dirname(controlFile));if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==process.getuid()||(parent.mode&0o777)!==0o700)throw Error('PRIVATE_CONTROL_REQUIRED');
 const h=await fs.open(sessionFile,require('fs').constants.O_RDONLY|require('fs').constants.O_NOFOLLOW);let session;
 try{const s=await h.stat();if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.size>16384)throw Error('PRIVATE_SESSION_REQUIRED');session=JSON.parse(await h.readFile('utf8'));}finally{await h.close();}
 const user=jwt.verify(session.token,secret,{algorithms:['HS256']});if(!Number.isSafeInteger(user.id)||user.pipelineOrchestrator===true)throw Error('OWNER_SESSION_REQUIRED');
 const rows=(await pool.query("SELECT c.expires_at,c.overall_deadline,c.active_lease_id,t.authorization FROM active_dast_commissioning_phases c JOIN active_dast_targets t ON t.id=c.target_id AND t.project_id=c.project_id AND t.pipeline_execution_id=c.pipeline_execution_id JOIN projects p ON p.id=c.project_id JOIN pipeline_executions e ON e.id=c.pipeline_execution_id AND e.project_id=p.id WHERE c.project_id=$1 AND c.pipeline_execution_id=$2 AND c.operator_id=$3 AND p.user_id=$3 AND e.status='RUNNING' AND c.phase='AWAITING_ACTIVE_AUTHORIZATION' AND c.runtime_retained AND c.expires_at>NOW()",[projectId,executionId,user.id])).rows;
 if(rows.length!==1)throw Error('AWAITING_EXECUTION_REQUIRED');
 const expiresAt=Math.min(Date.now()+240000,new Date(rows[0].expires_at).getTime());if(!Number.isSafeInteger(expiresAt)||expiresAt<=Date.now())throw Error('EXPIRED_CONTINUATION');
 const budget=require('../services/commissioningBudget');budget.requireTime(expiresAt,budget.minimumFor(rows[0].authorization));
 let leaseRecord=null;
 // A missing column means the unapplied source-only migration; retain the
 // historical signed path for offline callers, while production rows always
 // expose the lease columns and therefore fail closed until migration 015.
 if(Object.prototype.hasOwnProperty.call(rows[0],'overall_deadline')) {
  leaseRecord=await require('../services/commissioningPhaseLease').issue(pool,{projectId,executionId,userId:user.id},expiresAt,new Date(rows[0].overall_deadline||rows[0].expires_at).getTime());
 }
 const scope={projectId,executionId,userId:user.id,expiresAt:leaseRecord?.expiresAt||expiresAt,phase:'ACTIVE_COMMISSIONING',activeEnabled:true,...(leaseRecord?{leaseId:leaseRecord.leaseId}:{})};
 const mac=crypto.createHmac('sha256',Buffer.from(key,'hex')).update(JSON.stringify(scope)).digest('hex');
 await fs.writeFile(controlFile,JSON.stringify({scope,mac}),{mode:0o600,flag:'wx'});
 return {controlFile,projectId,executionId,userId:user.id,expiresAt,durationMs:Math.round(require('perf_hooks').performance.now()-started)};
}
if(require.main===module){
 require('dotenv').config({path:path.resolve(__dirname,'../.env'),quiet:true});process.env.DAST_ACTIVE_ENABLED='false';
 const pool=require('../db');
 const task=process.argv[2]==='--continuation'
 ?issueContinuation({pool,projectId:Number(process.argv[3]),executionId:Number(process.argv[4]),sessionFile:process.argv[5],secret:process.env.JWT_SECRET,key:process.env.DAST_COMMISSIONING_CONTROL_KEY,controlFile:process.env.DAST_COMMISSIONING_CONTROL_FILE,authorized:process.env.CS_COMMISSIONING_APPROVAL_ISSUANCE==='active-continuation-authorized'})
 :issue({pool,projectId:Number(process.argv[2]),sessionFile:process.argv[3],secret:process.env.JWT_SECRET,authorized:process.env.CS_COMMISSIONING_APPROVAL_ISSUANCE==='authorized'});
 task
 .then(result=>process.stdout.write(JSON.stringify(result)+'\n')).catch(()=>{process.stderr.write('COMMISSIONING_APPROVAL_ISSUANCE_BLOCKED\n');process.exitCode=1;}).finally(()=>pool.end());
}
module.exports={issue,issueContinuation};
