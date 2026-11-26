'use strict';
// Module 10 FE-4/FE-5 and policy UI: Kyverno denial parsing, server-side dry-run
// admission check, and PolicyReport / blocked-event summaries.
const {kubectlJson,projectNamespace,missingType}=require('./kubectlJson');

const RESULTS=['pass','fail','warn','error','skip'];
const clip=(s,n=500)=>String(s??'').slice(0,n);

// Parses Kyverno's admission denial, e.g.
//   admission webhook "validate.kyverno.svc-fail" denied the request:
//   resource Deployment/ns/app was blocked due to the following policies
//   require-run-as-non-root:
//     autogen-run-as-non-root: 'validation error: ...'
function parseKyvernoDenial(text){
 const s=String(text||'');
 const blocked=/admission webhook "[^"]*kyverno[^"]*" denied the request/i.test(s)||/was blocked due to the following policies/i.test(s);
 const resources=[...s.matchAll(/resource (\S+?) was blocked/g)].map(m=>m[1]);
 const violations=[];let policy=null;
 const section=s.split(/was blocked due to the following policies/i).slice(1).join('\n');
 for(const line of section.split(/\r?\n/)){
  const p=line.match(/^([a-z0-9][a-z0-9-.]*):\s*$/);
  if(p){policy=p[1];continue;}
  const r=line.match(/^\s+([a-z0-9][a-z0-9-.]*):\s*(.+)$/i);
  if(r&&policy)violations.push({policy,rule:r[1],message:clip(r[2].trim().replace(/^'(.*)'$/,'$1'))});
 }
 return {blocked,resources:[...new Set(resources)],violations};
}

function denialSummary(denial){
 if(!denial.violations.length)return 'admission denied by Kyverno';
 return denial.violations.map(v=>`${v.policy}/${v.rule}: ${v.message}`).join('; ');
}

// FE-4: server-side dry-run runs admission webhooks (Kyverno) without persisting.
// FE-5: an Enforce-mode denial fails the Deploy stage with the denial as the reason.
async function serverDryRun(execute,namespace,file,cwd,now=()=>new Date().toISOString()){
 const base={engine:'kubectl apply --dry-run=server',namespace,checkedAt:now()};
 try{
  const output=await execute('kubectl server dry-run','kubectl',['apply','--dry-run=server','--namespace',namespace,'-f',file],cwd,120000);
  return {...base,passed:true,violations:[],output:clip(output,2000)};
 }catch(error){
  const denial=parseKyvernoDenial(error.message);
  const result={...base,passed:false,blockedByPolicy:denial.blocked,resources:denial.resources,violations:denial.violations,output:clip(error.message,4000)};
  const failure=new Error(denial.blocked
   ?`Kyverno policy blocked deployment: ${denialSummary(denial)}`
   :`Server-side dry-run failed: ${clip(error.message,1000)}`);
  failure.code=denial.blocked?'KYVERNO_POLICY_BLOCKED':'SERVER_DRY_RUN_FAILED';
  failure.nonRetryable=denial.blocked;
  failure.policyValidation=result;
  throw failure;
 }
}

function inNamespace(resource,namespace){return !namespace||resource?.namespace===namespace;}

function summarizePolicyReports(reports,namespace){
 const byPolicy=new Map();
 for(const report of reports?.items||[]){
  for(const r of report.results||[]){
   // Kyverno >=1.10 writes one report per resource (scope); older reports list resources per result.
   const resources=r.resources?.length?r.resources:(report.scope?[report.scope]:[]);
   // Namespaced PolicyReports are already read with -n; cluster reports must be filtered.
   if(namespace&&report.kind==='ClusterPolicyReport'&&!resources.some(x=>inNamespace(x,namespace)))continue;
   const key=r.policy||'unknown';
   const row=byPolicy.get(key)||{policy:key,pass:0,fail:0,warn:0,error:0,skip:0,failures:[]};
   const result=RESULTS.includes(r.result)?r.result:'error';
   row[result]++;
   if(result==='fail'&&row.failures.length<10){
    const res=resources[0]||{};
    row.failures.push({rule:r.rule,resource:`${res.kind||'?'}/${res.name||'?'}`,message:clip(r.message,300)});
   }
   byPolicy.set(key,row);
  }
 }
 return [...byPolicy.values()].sort((a,b)=>b.fail-a.fail||a.policy.localeCompare(b.policy));
}

// Kyverno records each Enforce-mode denial as a PolicyViolation event on the policy.
function blockedEvents(events,namespace,limit=20){
 return (events?.items||[])
  .filter(e=>e.reason==='PolicyViolation'&&/blocked/i.test(e.message||'')&&(!namespace||String(e.message||'').includes(`${namespace}/`)))
  .map(e=>({time:e.lastTimestamp||e.eventTime||e.metadata?.creationTimestamp||null,policy:e.involvedObject?.name||null,count:e.count||1,message:clip(e.message,500)}))
  .sort((a,b)=>String(b.time).localeCompare(String(a.time)))
  .slice(0,limit);
}

// SRS FR-17.6: compliance score from Kyverno PolicyReport results for the namespace.
// score = pass / (pass + fail + warn + error); skip is not evaluated. No results -> no score (never 100 by default).
function complianceScore(results){
 const t=(results||[]).reduce((s,r)=>{for(const k of RESULTS)s[k]+=Number(r[k]||0);return s;},{pass:0,fail:0,warn:0,error:0,skip:0});
 const evaluated=t.pass+t.fail+t.warn+t.error;
 return {...t,evaluated,score:evaluated?Math.round((1000*t.pass)/evaluated)/10:null,
  basis:'Kyverno PolicyReport results in this namespace: pass / (pass + fail + warn + error); skip is not counted',
  text:evaluated?null:'No policy report results for this namespace yet'};
}

function clusterPolicies(list){
 return (list?.items||[]).map(p=>({name:p.metadata?.name,action:p.spec?.validationFailureAction||p.spec?.rules?.[0]?.validate?.failureAction||'Audit',
  ready:(p.status?.conditions||[]).some(c=>c.type==='Ready'&&c.status==='True'),rules:(p.spec?.rules||[]).length}));
}

async function projectPolicies(pool,userId,id,run=kubectlJson){
 const ns=await projectNamespace(pool,userId,id,run);
 if(ns.code)return ns;
 const out={projectId:ns.projectId,namespace:ns.namespace,observedAt:new Date().toISOString()};
 let policies;
 try{policies=await run(['get','clusterpolicies'])}
 catch(e){return {code:200,body:{...out,status:missingType(e)?'kyverno_not_installed':'not_connected',reason:missingType(e)?'Kyverno CRDs not found; install Kyverno (k8s/kyverno/README.md)':'ClusterPolicies could not be read'}};}
 const optional=args=>run(args).catch(e=>missingType(e)?{items:[]}:Promise.reject(e));
 try{
  const [reports,clusterReports,events]=await Promise.all([
   optional(['get','policyreports','-n',ns.namespace]),
   optional(['get','clusterpolicyreports']),
   optional(['get','events','-A','--field-selector','reason=PolicyViolation']),
  ]);
  const merged={items:[...(reports.items||[]),...(clusterReports.items||[])]};
  const results=summarizePolicyReports(merged,ns.namespace);
  return {code:200,body:{...out,status:'observed',policies:clusterPolicies(policies),results,compliance:complianceScore(results),blocked:blockedEvents(events,ns.namespace)}};
 }catch{return {code:200,body:{...out,status:'not_connected',reason:'Policy reports could not be read'}};}
}

module.exports={parseKyvernoDenial,denialSummary,serverDryRun,summarizePolicyReports,blockedEvents,clusterPolicies,projectPolicies,complianceScore};
