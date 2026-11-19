'use strict';
// Module 10 FE-3: per-namespace least-privilege RBAC and an RBAC analyzer.
const fs=require('node:fs'),path=require('node:path');
const {MANAGED_BY_LABEL,PROJECT_ID_LABEL}=require('./kubernetesNamespace');
const {kubectlJson,projectNamespace}=require('./kubectlJson');

const SERVICE_ACCOUNT='cloudsentinel-app';
const ROLE='cloudsentinel-app-read';
const ESCALATING_VERBS=['escalate','bind','impersonate'];

function rbacManifests(namespace,projectId){
 if(!/^cloudsentinel-p-[1-9]\d*$/.test(namespace||''))throw new Error('A valid CloudSentinel project namespace is required');
 const metadata=name=>({name,namespace,labels:{[MANAGED_BY_LABEL]:'cloudsentinel',[PROJECT_ID_LABEL]:String(projectId)}});
 return {apiVersion:'v1',kind:'List',items:[
  {apiVersion:'v1',kind:'ServiceAccount',metadata:metadata(SERVICE_ACCOUNT),automountServiceAccountToken:false},
  // Least privilege: the app may only read ConfigMaps in its own namespace. No wildcards.
  {apiVersion:'rbac.authorization.k8s.io/v1',kind:'Role',metadata:metadata(ROLE),rules:[{apiGroups:[''],resources:['configmaps'],verbs:['get','list']}]},
  {apiVersion:'rbac.authorization.k8s.io/v1',kind:'RoleBinding',metadata:metadata(ROLE),
   subjects:[{kind:'ServiceAccount',name:SERVICE_ACCOUNT,namespace}],roleRef:{apiGroup:'rbac.authorization.k8s.io',kind:'Role',name:ROLE}},
 ]};
}

// Applies the namespace RBAC through the deploy stage's command runner.
async function ensureProjectRbac(projectId,namespace,execute,cwd){
 const file=path.join(cwd,'.cloudsentinel-rbac.json');
 fs.writeFileSync(file,JSON.stringify(rbacManifests(namespace,projectId),null,2),'utf8');
 await execute('kubectl apply rbac','kubectl',['apply','--namespace',namespace,'-f',file],cwd,60000);
 return {serviceAccount:SERVICE_ACCOUNT,role:ROLE};
}

function ruleFlags(rule){
 const flags=[];
 if((rule.verbs||[]).includes('*'))flags.push('Wildcard verb');
 if((rule.resources||[]).includes('*'))flags.push('Wildcard resource');
 if((rule.apiGroups||[]).includes('*'))flags.push('Wildcard API group');
 for(const verb of ESCALATING_VERBS)if((rule.verbs||[]).includes(verb))flags.push(`Privilege escalation verb: ${verb}`);
 return flags;
}

function analyzeRbac({roles,roleBindings}){
 const roleRows=(roles?.items||[]).map(role=>{
  const rules=(role.rules||[]).map(r=>({apiGroups:r.apiGroups||[],resources:r.resources||[],verbs:r.verbs||[],resourceNames:r.resourceNames||[],flags:ruleFlags(r)}));
  return {kind:role.kind||'Role',name:role.metadata?.name,namespace:role.metadata?.namespace,rules,flags:[...new Set(rules.flatMap(r=>r.flags))]};
 });
 const bindingRows=(roleBindings?.items||[]).map(binding=>{
  const ref=binding.roleRef||{},flags=[];
  if(ref.kind==='ClusterRole'&&ref.name==='cluster-admin')flags.push('Binds cluster-admin');
  else if(ref.kind==='ClusterRole')flags.push(`References ClusterRole ${ref.name}`);
  const subjects=(binding.subjects||[]).map(s=>({kind:s.kind,name:s.name,namespace:s.namespace||null}));
  if(subjects.some(s=>s.kind==='Group'&&/^system:(authenticated|unauthenticated)$/.test(s.name)))flags.push('Grants access to all (un)authenticated users');
  return {name:binding.metadata?.name,namespace:binding.metadata?.namespace,roleRef:{kind:ref.kind,name:ref.name},subjects,flags};
 });
 const wildcardRoles=roleRows.filter(r=>r.flags.some(f=>f.startsWith('Wildcard'))).length;
 const clusterAdminBindings=bindingRows.filter(b=>b.flags.includes('Binds cluster-admin')).length;
 return {roles:roleRows,bindings:bindingRows,summary:{roles:roleRows.length,bindings:bindingRows.length,wildcardRoles,clusterAdminBindings,compliant:!wildcardRoles&&!clusterAdminBindings}};
}

async function projectRbac(pool,userId,id,run=kubectlJson){
 const ns=await projectNamespace(pool,userId,id,run);
 if(ns.code)return ns;
 try{
  const [roles,roleBindings]=await Promise.all([run(['get','roles','-n',ns.namespace]),run(['get','rolebindings','-n',ns.namespace])]);
  return {code:200,body:{projectId:ns.projectId,namespace:ns.namespace,status:'observed',observedAt:new Date().toISOString(),...analyzeRbac({roles,roleBindings})}};
 }catch{return {code:200,body:{projectId:ns.projectId,namespace:ns.namespace,status:'not_connected',reason:'RBAC objects could not be read'}};}
}

module.exports={SERVICE_ACCOUNT,ROLE,rbacManifests,ensureProjectRbac,analyzeRbac,ruleFlags,projectRbac};
