'use strict';
const {digest,policyFromEnvironment}=require('./deploymentEligibility');
const enabled=()=>process.env.PIPELINE_PROVENANCE_ENABLED==='true';
const canonical=url=>String(url).replace(/\.git\/?$/,'').replace(/\/$/,'').toLowerCase();
const validBranch=name=>typeof name==='string'&&/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(name)&&!name.includes('..')&&!name.includes('//')&&!name.endsWith('/')&&!name.endsWith('.')&&name.split('/').every(part=>!part.startsWith('.')&&!part.endsWith('.lock'));
const safe=(message,status=400)=>Object.assign(Error(message),{status,safe:true});
function pushIdentity(project,body,delivery,raw,policy){
 const repo=canonical(project.repo_url),branch=typeof body.ref==='string'?body.ref.replace(/^refs\/heads\//,''):null;
 if(!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(repo)||canonical(`https://github.com/${body.repository?.full_name}`)!==repo||!Number.isSafeInteger(body.repository?.id)||body.repository.id<1||(!body.ref?.startsWith?.('refs/heads/')||!validBranch(branch))||(typeof body.after!=='string'||!/^[a-f0-9]{40}$/.test(body.after))||/^0+$/.test(body.after)||body.deleted||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(delivery||''))throw safe('Invalid push provenance');
 const approval=policy?.approved===true&&Date.parse(policy.expiresAt)>Date.now()?policy.projects?.find(p=>p.projectId===project.id&&p.ownerId===project.user_id&&p.repositoryId===body.repository.id&&canonical(p.repository)===repo):null;
 if(branch!==(approval?.branch||body.repository.default_branch))throw safe('Push branch is not approved',403);
 return {repo,branch,commit:body.after,repositoryId:body.repository.id,payloadHash:require('node:crypto').createHash('sha256').update(raw).digest('hex'),policyDigest:approval?digest(policy):null,profile:approval?'STATIC_HTML':null};
}
async function registerPush(pool,project,body,delivery,raw,{policy}={}){
 if(policy===undefined)policy=policyFromEnvironment();
 const identity=pushIdentity(project,body,delivery,raw,policy),c=await pool.connect();
 try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock($1,$2)',[project.id,8]);
  const current=(await c.query('SELECT user_id,repo_url FROM projects WHERE id=$1 FOR SHARE',[project.id])).rows[0];if(!current||current.user_id!==project.user_id||canonical(current.repo_url)!==identity.repo)throw safe('Project ownership or repository changed',409);
  const old=await c.query('SELECT * FROM github_delivery_receipts WHERE delivery_id=$1',[delivery]);
  if(old.rows.length){const r=old.rows[0];if(r.project_id!==project.id||r.payload_sha256!==identity.payloadHash)throw safe('Webhook delivery replay mismatch',409);await c.query('COMMIT');return {executionId:r.pipeline_execution_id,duplicate:true};}
  const same=await c.query('SELECT pipeline_execution_id,policy_digest,profile FROM pipeline_source_revisions WHERE project_id=$1 AND repository_id=$2 AND branch=$3 AND commit_sha=$4',[project.id,identity.repositoryId,identity.branch,identity.commit]);
  if(same.rows.length){const r=same.rows[0];if(r.policy_digest!==identity.policyDigest||r.profile!==identity.profile)throw safe('Commit already bound to a different approval; explicit reconciliation required',409);await c.query('INSERT INTO github_delivery_receipts(delivery_id,project_id,payload_sha256,pipeline_execution_id) VALUES($1,$2,$3,$4)',[delivery,project.id,identity.payloadHash,r.pipeline_execution_id]);await c.query('COMMIT');return {executionId:r.pipeline_execution_id,duplicate:true};}
  const active=await c.query("SELECT id FROM pipeline_executions WHERE project_id=$1 AND status IN ('TRIGGERED','RUNNING') LIMIT 1",[project.id]);if(active.rows.length)throw safe('Pipeline is already active for this project.',409);
  const id=(await c.query("INSERT INTO pipeline_executions(project_id,status,triggered_by) VALUES($1,'TRIGGERED','webhook') RETURNING id",[project.id])).rows[0].id;
  await c.query('INSERT INTO pipeline_source_revisions(pipeline_execution_id,project_id,owner_id,repository_id,repository_identity,branch,commit_sha,policy_digest,profile) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[id,project.id,project.user_id,identity.repositoryId,identity.repo,identity.branch,identity.commit,identity.policyDigest,identity.profile]);
  await c.query('INSERT INTO github_delivery_receipts(delivery_id,project_id,payload_sha256,pipeline_execution_id) VALUES($1,$2,$3,$4)',[delivery,project.id,identity.payloadHash,id]);await c.query('COMMIT');return {executionId:id,duplicate:false};
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e}finally{c.release()}
}
async function revision(pool,context){
 if(!enabled()||!context.executionId)return null;
 const r=await pool.query('SELECT r.* FROM pipeline_source_revisions r JOIN projects p ON p.id=r.project_id AND p.user_id=r.owner_id WHERE r.pipeline_execution_id=$1 AND r.project_id=$2 AND r.owner_id=$3',[context.executionId,context.projectId,context.userId]);
 if(r.rows.length!==1)throw Error('PIPELINE_SOURCE_REVISION_MISSING');return r.rows[0];
}
async function git(args,cwd){try{return await require('./boundedCommand').run('git',args,{cwd,env:{...process.env,GIT_TERMINAL_PROMPT:'0',GIT_ASKPASS:'/bin/false'}})}catch{throw Error('PINNED_CHECKOUT_FAILED')}}
async function pin(pool,context,cwd,{run=git}={}){
 const r=await revision(pool,context);if(!r)return null;
 if(!/^[a-f0-9]{40}$/.test(r.commit_sha))throw Error('INVALID_EXECUTION_COMMIT');
 const remote=await run(['remote','get-url','origin'],cwd);let u;try{u=new URL(remote);u.username='';u.password=''}catch{throw Error('CHECKOUT_REPOSITORY_MISMATCH')}
 if(canonical(u.toString())!==r.repository_identity)throw Error('CHECKOUT_REPOSITORY_MISMATCH');
 await run(['fetch','--depth','1','origin',r.commit_sha],cwd);
 await run(['checkout','--detach',r.commit_sha],cwd);
 if(await run(['rev-parse','HEAD'],cwd)!==r.commit_sha)throw Error('CHECKOUT_COMMIT_MISMATCH');
 return r;
}
module.exports={enabled,canonical,validBranch,pushIdentity,registerPush,revision,pin,git};
