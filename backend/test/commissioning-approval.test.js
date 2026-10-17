'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs/promises'),os=require('os'),path=require('path'),jwt=require('jsonwebtoken');
test('private approval issuance verifies a normal user session and actual ownership without signing a new session',async t=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'cs-approval-unit-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const sessionFile=path.join(root,'session.json'),secret='OFFLINE_TEST_ONLY';await fs.writeFile(sessionFile,JSON.stringify({token:jwt.sign({id:7},secret,{expiresIn:'5m'})}),{mode:0o600});
 const calls=[],pool={async query(sql,args){calls.push({sql,args});return {rows:[{id:7}]};}};
 const issue=require('../scripts/commissioning-approval').issue;
 const result=await issue({pool,projectId:42,sessionFile,secret,authorized:true});t.after(()=>fs.rm(result.directory,{recursive:true,force:true}));
 assert.equal(result.userId,7);assert.ok(calls.every(c=>c.sql.startsWith('SELECT ')));assert.ok(!JSON.stringify(result).includes('approval"'));
 assert.equal((await fs.stat(result.directory)).mode&0o777,0o700);const file=path.join(result.directory,'approval.json');assert.equal((await fs.stat(file)).mode&0o777,0o600);const value=JSON.parse(await fs.readFile(file,'utf8'));assert.match(value.approval,/^[a-f0-9]{64}$/);assert.equal(value.scope.projectId,42);
 for(const patch of [{authorized:false},{projectId:17},{secret:'WRONG'},{pool:{async query(){return {rows:[]};}}}])await assert.rejects(issue({pool,projectId:42,sessionFile,secret,authorized:true,...patch}));
 await fs.chmod(sessionFile,0o644);await assert.rejects(issue({pool,projectId:42,sessionFile,secret,authorized:true}));
});
test('separate signed continuation enables only its exact scope without changing the production flag',async t=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'cs-continuation-unit-'));await fs.chmod(root,0o700);t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const sessionFile=path.join(root,'session.json'),controlFile=path.join(root,'control.json'),secret='OFFLINE_TEST_ONLY',key='e'.repeat(64),ctx={projectId:42,executionId:100,userId:7};
 await fs.writeFile(sessionFile,JSON.stringify({token:jwt.sign({id:7},secret,{expiresIn:'5m'})}),{mode:0o600});
 const keys=['DAST_ACTIVE_ENABLED','DAST_ACTIVE_COMMISSIONING_ENABLED','DAST_ACTIVE_COMMISSIONING_CONTEXT','DAST_COMMISSIONING_CONTROL_FILE','DAST_COMMISSIONING_CONTROL_KEY'];const old=keys.map(k=>process.env[k]);t.after(()=>keys.forEach((k,i)=>{if(old[i]===undefined)delete process.env[k];else process.env[k]=old[i];}));
 Object.assign(process.env,{DAST_ACTIVE_ENABLED:'false',DAST_ACTIVE_COMMISSIONING_ENABLED:'true',DAST_ACTIVE_COMMISSIONING_CONTEXT:JSON.stringify({...ctx,expiresAt:Date.now()+600000}),DAST_COMMISSIONING_CONTROL_FILE:controlFile,DAST_COMMISSIONING_CONTROL_KEY:key});
 const allowed=require('../services/activeDastCommissioning').activeAllowed;assert.equal(allowed(ctx),false);
 const pool={async query(sql){assert.ok(sql.startsWith('SELECT '));return {rows:[{expires_at:new Date(Date.now()+240000)}]};}};
 const issueContinuation=require('../scripts/commissioning-approval').issueContinuation;
 for(const rows of [[],[{expires_at:new Date(Date.now()+173000)}],[{expires_at:new Date(Date.now()-1)}]]){
  await assert.rejects(issueContinuation({pool:{async query(sql){assert.match(sql,/phase='AWAITING_ACTIVE_AUTHORIZATION'/);assert.match(sql,/runtime_retained/);return {rows};}},projectId:42,executionId:100,sessionFile,secret,key,controlFile,authorized:true}));
  await assert.rejects(fs.stat(controlFile),{code:'ENOENT'});
 }
 await assert.rejects(issueContinuation({pool,projectId:42,executionId:100,sessionFile,secret,key,controlFile,authorized:false}));
 const result=await issueContinuation({pool,projectId:42,executionId:100,sessionFile,secret,key,controlFile,authorized:true});assert.equal(result.executionId,100);assert.equal(process.env.DAST_ACTIVE_ENABLED,'false');assert.equal(allowed(ctx),true);assert.equal(allowed({...ctx,executionId:101}),false);
 await assert.rejects(issueContinuation({pool,projectId:42,executionId:100,sessionFile,secret,key,controlFile,authorized:true}));
 const record=JSON.parse(await fs.readFile(controlFile,'utf8'));record.scope.activeEnabled=false;await fs.writeFile(controlFile,JSON.stringify(record));assert.equal(allowed(ctx),false);
 record.scope.activeEnabled=true;await fs.writeFile(controlFile,JSON.stringify(record));await fs.chmod(controlFile,0o644);assert.equal(allowed(ctx),false);
});
