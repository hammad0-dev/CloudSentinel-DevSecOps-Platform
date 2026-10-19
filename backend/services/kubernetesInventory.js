'use strict';
const {execFile}=require('node:child_process');
const execute=require('node:util').promisify(execFile);
const {PROJECT_ID_LABEL,MANAGED_BY_LABEL}=require('./kubernetesNamespace');
async function kubectl(args){
 const {stdout}=await execute('kubectl',args,{timeout:8000,maxBuffer:2*1024*1024});
 return JSON.parse(stdout);
}
function observations(pods){
 const issues=[];
 for(const pod of pods){
  const podContext=pod.spec?.securityContext||{};
  for(const c of [...(pod.spec?.containers||[]),...(pod.spec?.initContainers||[])]){
   const sc={...podContext,...c.securityContext};
   const add=(severity,issue,recommendation)=>issues.push({severity,namespace:pod.metadata.namespace,resource:pod.metadata.name,kind:'Pod',issue:`${c.name}: ${issue}`,recommendation});
   if(sc.privileged===true)add('HIGH','Privileged container configured','Set privileged: false');
   if(sc.runAsUser===0)add('HIGH','Explicit root UID configured','Use a nonzero runAsUser with runAsNonRoot: true');
   else if(sc.runAsNonRoot!==true)add('INFO','Non-root execution is not enforced; actual image UID unknown','Verify image UID and set runAsNonRoot: true');
   if(sc.runAsUser===0&&sc.runAsNonRoot===true)add('HIGH','Root UID conflicts with runAsNonRoot','Set a consistent nonzero UID');
   if(!c.resources?.limits?.cpu||!c.resources?.limits?.memory)add('MEDIUM','CPU or memory limit missing','Set both CPU and memory limits');
   if(!String(c.image||'').includes('@sha256:'))add('LOW','Image reference is mutable (not digest pinned)','Pin a verified image digest');
   if((pod.spec?.containers||[]).includes(c)){
    if(!c.readinessProbe)add('LOW','Readiness probe missing','Configure an application readiness probe');
    if(!c.livenessProbe)add('LOW','Liveness probe missing','Configure an application liveness probe');
   }
  }
 }
 return issues;
}
async function inventory(projectId,records,run=kubectl){
 const base={projectId,status:'not_deployed',clusterType:'Local Minikube',eks:'Not configured',observedAt:new Date().toISOString(),assessment:'Workload specification observations only; full security assessment not implemented'};
 if(!records.length)return base;
 try{
  const expected=process.env.KUBERNETES_MINIKUBE_CONTEXT||'minikube';
  const config=await run(['config','view','--minify','-o','json']);
  const context=config.contexts?.find(c=>c.name===config['current-context']);
  if(!context||context.name!==expected||context.context?.cluster!==expected)throw Error('Context mismatch');
  const get=(type,extra=[])=>run(['--context',expected,'--request-timeout=5s','get',type,...extra,'-o','json']);
  // Namespace mappings are verified from actual ownership labels, not inferred names.
  const ns=await get('namespaces',['-l',`${PROJECT_ID_LABEL}=${projectId},${MANAGED_BY_LABEL}=cloudsentinel`]);
  if(!Array.isArray(ns.items)||ns.items.length>20)throw Error('Invalid or excessive namespace inventory');
  const namespaces=ns.items.map(n=>{
   const m=n.metadata,l=m?.labels||{};
   if(l[PROJECT_ID_LABEL]!==String(projectId)||l[MANAGED_BY_LABEL]!=='cloudsentinel'||!/^([a-z0-9]([-a-z0-9]*[a-z0-9])?)$/.test(m.name))throw Error('Ownership mismatch');
   return m.name;
  });
  if(!namespaces.length)return {...base,context:expected};
  const names=new Set(records.map(r=>r.app_name).filter(Boolean));
  const results=await Promise.all(namespaces.map(async namespace=>{
   const [deployments,pods]=await Promise.all([get('deployments',['-n',namespace]),get('pods',['-n',namespace])]);
   if(!Array.isArray(deployments.items)||!Array.isArray(pods.items))throw Error('Malformed inventory');
   if([...deployments.items,...pods.items].some(r=>r.metadata?.namespace!==namespace))throw Error('Namespace mismatch');
   const deployed=deployments.items.filter(d=>names.has(d.metadata.name)&&d.metadata.labels?.['managed-by']==='cloudsentinel');
   // Project-owned namespaces only, then select pods of recorded managed applications.
   const apps=new Set(deployed.map(d=>d.metadata.name));
   return {namespace,deployments:deployed,pods:pods.items.filter(p=>apps.has(p.metadata.labels?.app))};
  }));
  const deployments=results.flatMap(r=>r.deployments),pods=results.flatMap(r=>r.pods);
  if(!deployments.length)return {...base,context:expected};
  const ready=p=>p.status?.conditions?.some(c=>c.type==='Ready'&&c.status==='True');
  return {...base,status:'observed',context:expected,namespaces:results.filter(r=>r.deployments.length).map(r=>r.namespace),
   counts:{namespaces:results.filter(r=>r.deployments.length).length,pods:pods.length,running:pods.filter(p=>p.status?.phase==='Running').length,ready:pods.filter(ready).length,desiredReplicas:deployments.reduce((n,d)=>n+(d.spec?.replicas??1),0),readyReplicas:deployments.reduce((n,d)=>n+(d.status?.readyReplicas||0),0)},
   deployments:deployments.map(d=>({name:d.metadata.name,namespace:d.metadata.namespace,desired:d.spec?.replicas??1,ready:d.status?.readyReplicas||0,available:d.status?.availableReplicas||0})),
   pods:pods.map(p=>({name:p.metadata.name,namespace:p.metadata.namespace,phase:p.status?.phase||'Unknown',ready:!!ready(p),restarts:[...(p.status?.containerStatuses||[]),...(p.status?.initContainerStatuses||[])].reduce((n,c)=>n+(c.restartCount||0),0),images:(p.spec?.containers||[]).map(c=>c.image)})),issues:observations(pods)};
 }catch{return {...base,status:'not_connected',reason:'Minikube unavailable, context mismatch, insufficient read permissions or unverifiable inventory'};}
}
async function projectInventory(pool,userId,id,read=inventory){
 if(!/^[1-9]\d*$/.test(String(id))||!Number.isSafeInteger(Number(id)))return {code:400,body:{error:'Valid project required'}};
 const {rows}=await pool.query('SELECT id FROM projects WHERE id=$1 AND user_id=$2',[Number(id),userId]);
 if(!rows.length)return {code:404,body:{error:'Project not found'}};
 const history=await pool.query("SELECT DISTINCT app_name FROM deployment_history WHERE project_id=$1 AND status='SUCCESS' AND app_name IS NOT NULL",[Number(id)]);
 return {code:200,body:await read(Number(id),history.rows)};
}
module.exports={inventory,projectInventory,observations};
