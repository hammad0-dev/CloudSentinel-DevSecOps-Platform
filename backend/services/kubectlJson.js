'use strict';
// Read-only kubectl JSON access for project-scoped Kubernetes views (Module 10).
const {execFile}=require('node:child_process');
const exec=require('node:util').promisify(execFile);
const {getProjectNamespace,assertNamespaceOwnership}=require('./kubernetesNamespace');

const context=()=>process.env.KUBERNETES_MINIKUBE_CONTEXT||'minikube';

async function kubectlJson(args){
 const {stdout}=await exec('kubectl',['--context',context(),'--request-timeout=5s',...args,'-o','json'],{timeout:10000,maxBuffer:8*1024*1024});
 return JSON.parse(stdout);
}

const notFound=e=>/notfound|not found/i.test(`${e?.stderr||''} ${e?.message||''}`);
const missingType=e=>/doesn't have a resource type|no matches for kind|the server could not find the requested resource/i.test(`${e?.stderr||''} ${e?.message||''}`);

// Authorizes the project for this user and resolves its CloudSentinel-owned namespace.
async function projectNamespace(pool,userId,id,run=kubectlJson){
 if(!/^[1-9]\d*$/.test(String(id))||!Number.isSafeInteger(Number(id)))return {code:400,body:{error:'Valid project required'}};
 const projectId=Number(id);
 const {rows}=await pool.query('SELECT id FROM projects WHERE id=$1 AND user_id=$2',[projectId,userId]);
 if(!rows.length)return {code:404,body:{error:'Project not found'}};
 const namespace=getProjectNamespace(projectId);
 try{assertNamespaceOwnership(await run(['get','namespace',namespace]),projectId);}
 catch(e){
  if(notFound(e))return {code:200,body:{projectId,namespace,status:'not_deployed'}};
  return {code:200,body:{projectId,namespace,status:'not_connected',reason:'Minikube unavailable, context mismatch or namespace ownership unverifiable'}};
 }
 return {projectId,namespace};
}

module.exports={kubectlJson,projectNamespace,missingType,notFound};
