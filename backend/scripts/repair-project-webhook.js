'use strict';
// Register a missing hook for an existing project; never starts a pipeline or scan.
require('dotenv').config({path:require('path').join(__dirname,'../.env'),quiet:true});
const axios=require('axios'),pool=require('../db');
async function repair(){
 const id=process.argv[2];if(!/^\d+$/.test(id||''))throw Error('Usage: node scripts/repair-project-webhook.js PROJECT_ID');
 const p=(await pool.query('SELECT id,name,repo_url,github_token,webhook_secret,webhook_id FROM projects WHERE id=$1',[id])).rows[0];
 if(!p)throw Error('Project not found');
 if(!p.github_token||!p.webhook_secret)throw Error('Project requires a stored GitHub token and webhook secret');
 const repo=new URL(p.repo_url);
 if(repo.hostname!=='github.com')throw Error('Only github.com repositories are supported');
 const parts=repo.pathname.replace(/\.git\/?$/,'').split('/').filter(Boolean);
 if(parts.length!==2||parts.some(part=>! /^[\w.-]+$/.test(part)))throw Error('Invalid repository URL');
 const target=new URL('/api/webhooks/github',process.env.PUBLIC_URL);
 if(target.protocol!=='https:')throw Error('PUBLIC_URL must use public HTTPS');
 const base=`https://api.github.com/repos/${parts.map(encodeURIComponent).join('/')}/hooks`;
 const headers={Authorization:`Bearer ${p.github_token.trim()}`,Accept:'application/vnd.github+json'};
 const hooks=[];
 for(let page=1;;page++){const r=await axios.get(base,{headers,params:{per_page:100,page},timeout:15000});hooks.push(...r.data);if(r.data.length<100)break;}
 if(p.webhook_id){const hook=hooks.find(h=>String(h.id)===String(p.webhook_id));if(hook?.active&&hook.config?.url===target.href&&hook.events.includes('push')){console.log(`Project ${p.id}: webhook already registered and active.`);return;}throw Error('Existing webhook configuration needs review; no hook was overwritten');}
 if(hooks.some(h=>h.config?.url===target.href))throw Error('A hook already points to this callback; refusing to overwrite an unlinked hook');
 const created=await axios.post(base,{name:'web',active:true,events:['push'],config:{url:target.href,content_type:'json',secret:p.webhook_secret,insecure_ssl:'0'}},{headers,timeout:15000});
 const stored=await pool.query('UPDATE projects SET webhook_id=$1 WHERE id=$2 AND webhook_id IS NULL',[String(created.data.id),p.id]);
 if(stored.rowCount!==1)throw Error('Hook created but project changed concurrently; review GitHub webhook configuration');
 console.log(`Project ${p.id}: webhook registered. Push a new commit to trigger the pipeline.`);
}
repair().catch(e=>{const status=e.response?.status;console.error(status===403?'GitHub denied webhook access (403). Grant this token Webhooks: Read and write for the repository, then retry.':status?`GitHub webhook request failed (HTTP ${status}).`:e.message);process.exitCode=1;}).finally(()=>pool.end());
