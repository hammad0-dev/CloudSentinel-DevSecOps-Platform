import {useEffect,useState} from 'react';
import api from '../lib/api';

// EKS container workload (Module 8): detected structure, planned resources, exact-hash approval and gated apply.
export default function WorkloadInfrastructure({projectId}){
 const [record,setRecord]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 useEffect(()=>{let active=true;setRecord(null);setError('');api.get(`/infrastructure/${projectId}/workload`).then(r=>{if(active)setRecord(r.data)}).catch(()=>{if(active)setError('Workload infrastructure status unavailable')});return()=>{active=false}},[projectId]);
 async function action(name,body={}){setBusy(true);setError('');try{const r=await api.post(`/infrastructure/${projectId}/workload/${name}`,body,{timeout:600000});setRecord(r.data)}catch(e){setError(e.response?.data?.error||'Operation unavailable')}finally{setBusy(false)}}
 const c=record?.classification,plan=record?.plan,dplan=record?.destroyPlan;
 return <section className="space-y-3 border-t border-slate-700 pt-4"><h4 className="font-bold">Container workload on EKS</h4>
  <p className="text-sm text-slate-400">Fixed Terraform templates; only validated values are generated. Account {record?.account||'229032674007'} • {record?.region||'ap-south-1'}.</p>
  <p>Status: {record?.status||'NOT_CONFIGURED'} • Apply: {record?.applyEnabled?'enabled (gated by approval)':'disabled'}</p>
  {record?.applyBlockers?.length>0&&<p className="text-amber-300 text-sm">{record.applyBlockers.join('; ')}</p>}
  {c&&<div><p>Structure: {c.architecture} • {c.result} • {c.reason}</p>
   {c.components?.map(x=><p key={x.name}>{x.name}: {x.stack}{x.framework?`/${x.framework}`:''} • port {x.port} ({x.portSource}) • {x.public?'public LoadBalancer':'private'} • Dockerfile {x.dockerfile} • secret keys {x.secretKeys.length?x.secretKeys.join(', '):'none'}</p>)}
   {c.database&&<p>Database: RDS {c.database.engine} (db.t3.micro, private, encrypted, RDS-managed password)</p>}
   {c.needsConfirmation?.map(n=><p key={n.component} className="text-amber-300">Confirm {n.field} for {n.component}: {n.reason}</p>)}
   {c.warnings?.map(w=><p key={w} className="text-amber-300 text-sm">{w}</p>)}</div>}
  {plan&&<div><p className="font-mono break-all">Plan SHA-256: {plan.hash}</p><p>Expires {plan.expiresAt}</p>{plan.summary.map(r=><p key={r.address} className="text-sm">{r.actions.join(',')} {r.type} — {r.address}</p>)}</div>}
  {dplan&&<p className="font-mono break-all">Destroy plan SHA-256: {dplan.hash} ({dplan.summary.length} deletions)</p>}
  {record?.approval&&<p>Approved {record.approval.kind} {record.approval.hash.slice(0,12)}… {record.approval.consumedAt?'(used)':`(single use, expires ${record.approval.expiresAt})`}</p>}
  {busy&&<p role="status">Operation in progress…</p>}{error&&<p role="alert">{error}</p>}
  <div className="flex flex-wrap gap-3">
   <button className="border border-slate-600 rounded p-2" disabled={busy} onClick={()=>action('analyze')}>Analyze for EKS</button>
   {c?.result==='CONTAINER'&&<button className="border border-slate-600 rounded p-2" disabled={busy} onClick={()=>action('confirm',{architecture:c.architecture})}>Confirm {c.architecture}</button>}
   {record?.status==='CONFIRMED'&&<button className="border border-slate-600 rounded p-2" disabled={busy} onClick={()=>action('plan')}>Plan</button>}
   {record?.status==='AWAITING_APPROVAL'&&!record.approval&&<button className="border border-slate-600 rounded p-2" disabled={busy} onClick={()=>action('approve',{hash:plan.hash})}>Approve this exact plan</button>}
   {record?.status==='AWAITING_APPROVAL'&&record.approval&&<button className="border border-slate-600 rounded p-2" disabled={busy||!record.applyEnabled} onClick={()=>action('apply')}>Apply approved plan</button>}
   {record?.status==='APPLIED'&&<button className="border border-slate-600 rounded p-2" disabled={busy} onClick={()=>action('destroy-plan')}>Plan destroy</button>}
   {record?.status==='AWAITING_DESTROY_APPROVAL'&&!record.approval?.kind?.startsWith('destroy')&&<button className="border border-slate-600 rounded p-2" disabled={busy} onClick={()=>action('approve',{hash:dplan.hash,kind:'destroy'})}>Approve destroy plan</button>}
   {record?.status==='AWAITING_DESTROY_APPROVAL'&&record.approval?.kind==='destroy'&&<button className="border border-slate-600 rounded p-2" disabled={busy||!record.applyEnabled} onClick={()=>action('destroy')}>Destroy</button>}
  </div>
  <p className="text-sm text-slate-400">Costs: EKS, RDS, load balancers, NAT and CloudWatch are billed per hour or per GB. Nothing is applied without an approved plan hash.</p>
 </section>;
}
