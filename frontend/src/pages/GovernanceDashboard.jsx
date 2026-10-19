import { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useSearchParams } from 'react-router-dom';
import { ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, LineChart, Line, CartesianGrid } from 'recharts';
import api from '../lib/api';
import PageHeader from '../components/PageHeader';
import SeverityBadge from '../components/SeverityBadge';
import ComplianceOverview from '../components/ComplianceOverview';

const sources=['SAST','DEPENDENCY','IAC','IMAGE','DAST','ACTIVE_DAST'];
const severities=['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'];
const statuses=['OPEN','RESOLVED','ACCEPTED_RISK','FALSE_POSITIVE'];
const colors=['#f85149','#f0883e','#d29922','#58a6ff','#8b949e','#bc8cff'];
const tabs=[['/dashboard','Unified Dashboard'],['/findings','Vulnerability Findings'],['/compliance','Compliance Overview'],['/analytics','Security Analytics'],['/reports','Reports']];
const date=value=>value?new Date(value).toLocaleString():'Not available';
function Chart({title,data,type='bar',label='name'}) {
 const populated=data?.some(d=>d.value>0);
 return <section className="card p-4 min-w-0"><h2 className="font-semibold mb-3">{title}</h2><div className="h-64">
 {!populated?<p className="text-sm text-[var(--text-secondary)]">No observations available for this selection.</p>:<ResponsiveContainer width="100%" height="100%">
 {type==='pie'?<PieChart><Pie data={data} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75}>{data.map((d,i)=><Cell key={d.name} fill={colors[i%colors.length]}/>)}</Pie><Tooltip/><Legend/></PieChart>:type==='line'?<LineChart data={data}><CartesianGrid stroke="var(--border-subtle)"/><XAxis dataKey={label}/><YAxis allowDecimals={false}/><Tooltip/><Line dataKey="value" name="Observed findings" stroke={colors[3]} type="linear"/></LineChart>:<BarChart data={data}><XAxis dataKey={label} tick={{fontSize:10}} interval={0}/><YAxis allowDecimals={false}/><Tooltip/><Bar dataKey="value" name="Findings / controls" fill={colors[3]}/></BarChart>}
 </ResponsiveContainer>}</div></section>;
}
export default function GovernanceDashboard() {
 const {pathname}=useLocation();const [params,setParams]=useSearchParams();
 const [projects,setProjects]=useState([]),[summary,setSummary]=useState(null),[listing,setListing]=useState(null);
 const [loading,setLoading]=useState(true),[error,setError]=useState(''),[revision,setRevision]=useState(0),[syncInfo,setSyncInfo]=useState(null);
 const [detail,setDetail]=useState(null),[detailLoading,setDetailLoading]=useState(false),[detailError,setDetailError]=useState(''),[detailId,setDetailId]=useState(null);
 const [status,setStatus]=useState('OPEN'),[reason,setReason]=useState(''),[saving,setSaving]=useState(false),[exporting,setExporting]=useState('');
 const initialized=useRef(false),detailRef=useRef(null),detailRequest=useRef(null);
 const query=params.toString();const page=Number(params.get('page')||1);
 const change=(key,value)=>{const next=new URLSearchParams(params);if(value)next.set(key,value);else next.delete(key);next.delete('page');if(key==='owaspVersion')next.delete('mapping');setParams(next);};
 useEffect(()=>{
  const controller=new AbortController();let live=true;
  async function load(){setLoading(true);setError('');setDetail(null);setDetailId(null);
   try {
    if(!initialized.current){const response=await api.post('/governance/sync',{}, {signal:controller.signal});if(live){setSyncInfo(response.data);initialized.current=true;}}
    const [p,s,l]=await Promise.all([api.get('/projects',{signal:controller.signal}),api.get(`/governance/summary?${query}`,{signal:controller.signal}),api.get(`/governance/findings?${query}`,{signal:controller.signal})]);
    if(live){setProjects(p.data.projects||[]);setSummary(s.data);setListing(l.data);}
   }catch(e){if(live&&!controller.signal.aborted){setError(e.response?.data?.error||'Unable to load governance records.');setSummary(null);setListing(null);}}
   finally{if(live)setLoading(false);}
  }load();return()=>{live=false;controller.abort();};
 },[query,revision]);
 useEffect(()=>{
  if(!detailId)return;
  const previous=document.activeElement;detailRef.current?.focus();
  const trap=e=>{if(e.key!=='Tab')return;const nodes=detailRef.current?.querySelectorAll('button:not(:disabled),input,select,textarea,a[href]');if(!nodes?.length)return;const first=nodes[0],last=nodes[nodes.length-1];if(e.shiftKey&&(document.activeElement===first||document.activeElement===detailRef.current)){e.preventDefault();last.focus();}else if(!e.shiftKey&&(document.activeElement===last||document.activeElement===detailRef.current)){e.preventDefault();first.focus();}};
  document.addEventListener('keydown',trap);return()=>{document.removeEventListener('keydown',trap);detailRequest.current?.abort();previous?.focus();};
 },[detailId]);
 useEffect(()=>{const close=e=>{if(e.key==='Escape'){setDetail(null);setDetailId(null);}};window.addEventListener('keydown',close);return()=>window.removeEventListener('keydown',close);},[]);
 async function inspect(id){detailRequest.current?.abort();const controller=new AbortController();detailRequest.current=controller;setDetailId(id);setDetail(null);setDetailLoading(true);setDetailError('');setReason('');try{const r=await api.get(`/governance/findings/${id}`,{signal:controller.signal});setDetail(r.data);setStatus(r.data.finding.status);}catch(e){if(!controller.signal.aborted)setDetailError(e.response?.data?.error||'Unable to load finding');}finally{if(!controller.signal.aborted)setDetailLoading(false);}}
 async function save(){setSaving(true);setDetailError('');try{await api.patch(`/governance/findings/${detail.finding.id}/status`,{status,reason});setDetail(null);setDetailId(null);setRevision(r=>r+1);}catch(e){setDetailError(e.response?.data?.error||'Unable to save status');}finally{setSaving(false);}}
 async function download(kind){setExporting(kind);setError('');try{const response=await api.get(`/governance/export/${kind}?${query}`,{responseType:'blob'});const url=URL.createObjectURL(response.data);const a=document.createElement('a');a.href=url;a.download=`cloudsentinel-${kind}.${kind.endsWith('csv')?'csv':'pdf'}`;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch{setError('Export failed. Please retry.');}finally{setExporting('');}}
 const refresh=()=>{initialized.current=false;setRevision(r=>r+1);};
 const isCompliance=pathname==='/compliance',isReports=pathname==='/reports',isFindings=pathname==='/findings';
 const chooseMapping=id=>{const next=new URLSearchParams(params);if(id)next.set('mapping',id);else next.delete('mapping');next.delete('page');window.scrollTo(0,0);setParams(next);};
 return <div className="space-y-5 min-w-0 governance-page">
 <PageHeader title={tabs.find(t=>t[0]===pathname)?.[1]||'Unified Dashboard'} subtitle="Stored security evidence across your projects" actions={<button className="secondary-btn" disabled={loading} onClick={refresh}>Refresh stored results</button>}/>
 <nav aria-label="Governance navigation" className="flex gap-2 flex-wrap">{tabs.map(([to,label])=><Link key={to} to={`${to}?${query}`} aria-current={pathname===to?'page':undefined} className={pathname===to?'primary-btn':'secondary-btn'}>{label}</Link>)}</nav>
 <form className="card p-4 flex flex-wrap items-end gap-3" onSubmit={e=>e.preventDefault()} aria-label="Finding filters">
 <label>Project<select aria-label="Project" className="input block" value={params.get('project')||''} onChange={e=>change('project',e.target.value)}><option value="">All projects</option>{projects.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
 {[['severity',severities],['source',sources],['status',statuses]].map(([key,values])=><label key={key} className="capitalize">{key}<select aria-label={key} className="input block" value={params.get(key)||''} onChange={e=>change(key,e.target.value)}><option value="">All {key}</option>{values.map(v=><option key={v}>{v}</option>)}</select></label>)}
 <label>Search<input aria-label="Search findings" className="input block" placeholder="Title, CVE or rule" maxLength={200} value={params.get('search')||''} onChange={e=>change('search',e.target.value)}/></label>
 {['from','to'].map(key=><label key={key} className="capitalize">{key} (UTC)<input aria-label={key} type="date" className="input block" value={params.get(key)||''} onChange={e=>change(key,e.target.value)}/></label>)}
 <label>Sort<select aria-label="Sort" className="input block" value={params.get('sort')||'severity'} onChange={e=>change('sort',e.target.value)}><option value="severity">Severity first</option><option value="newest">Newest detection</option><option value="oldest">Oldest detection</option></select></label>
 <button className="secondary-btn" onClick={()=>setParams({})}>Clear filters</button>
 {params.get('mapping')&&<span>Mapping: {params.get('mapping')} <button className="secondary-btn" onClick={()=>change('mapping','')}>Remove</button></span>}
 </form>
 {error&&<div role="alert" className="card p-4 text-red-400">{error} <button onClick={refresh} className="secondary-btn">Retry</button></div>}
 {loading&&<p role="status" className="card p-6">Loading stored assessments…</p>}
 {!loading&&summary&&<>
 <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3">{[{name:'Total',value:summary.total},...summary.bySeverity,{name:'Security posture',value:summary.score.value===null?'Not assessed':`${summary.score.value}/100`}].map(x=><div key={x.name} className="card p-4"><p className="text-sm text-[var(--text-secondary)]">{x.name}</p><p className="text-2xl font-bold">{x.value}</p></div>)}</div>
 <div className="card p-4 space-y-2"><p>Assessment coverage: {summary.score.assessedSlots}/{summary.score.totalSlots} project/scanner slots with complete stored details.</p><details><summary className="cursor-pointer">Scoring method and limitations</summary><p className="text-sm mt-2">{summary.score.methodology}</p></details>
 <p className="text-xs text-[var(--text-secondary)]">Kubernetes audits are unavailable here because stored records lack project ownership. Earlier dependency/IaC detail may have been replaced by upstream scans. Refresh imports stored records only.</p>
 {syncInfo?.sources.filter(s=>s.state==='UNAVAILABLE').map(s=><p className="text-sm" key={s.source}>{s.source}: {s.reason}</p>)}</div>
 {(isReports||isFindings)&&<section className="card p-4 space-y-3"><h2 className="font-semibold">Security & Compliance Reports</h2><p>Exports include every matching finding, across all pages, with the filters above. PDFs include coverage, limitations, evidence links and remediation.</p><div className="flex gap-2 flex-wrap">{['security','compliance','csv','compliance-csv'].map(kind=><button className="primary-btn" disabled={!!exporting} key={kind} onClick={()=>download(kind)}>{exporting===kind?'Generating…':kind==='csv'?'Download findings CSV':kind==='compliance-csv'?'Download compliance CSV':`Download ${kind} PDF`}</button>)}</div></section>}
 {!isReports&&!isFindings&&!isCompliance&&<>
 <div className="grid lg:grid-cols-2 gap-4"><Chart title="Severity distribution" data={summary.bySeverity} type="pie"/><Chart title="Findings by project" data={summary.byProject}/><Chart title="Findings by scanning module" data={summary.bySource}/><Chart title="Finding lifecycle (current status)" data={summary.byStatus} type="pie"/><Chart title={summary.trendLabel} data={summary.trend} type="line" label="day"/><Chart title={`${summary.compliance.version} distribution`} data={summary.compliance.owasp.map(c=>({name:c.id,value:c.findings}))}/><Chart title="CIS registered control assessments" data={Object.entries(summary.compliance.cisSummary).map(([name,value])=>({name,value}))}/></div>
 <section className="card p-4"><h2 className="font-semibold mb-3">Highest priority unresolved issues</h2>{!summary.priority.length?<p>No unresolved findings in this selection.</p>:summary.priority.map(f=><button className="block text-left py-2 hover:underline" onClick={()=>inspect(f.id)} key={f.id}><SeverityBadge severity={f.severity}/> {f.title} — {f.project_name}</button>)}</section>
 <section className="card p-4 overflow-auto"><h2 className="font-semibold mb-3">Latest stored scans per project and source</h2>{!summary.recentScans.length?<p>No stored scans available.</p>:<table className="gh-table"><thead><tr><th>Project</th><th>Source / Scan ID</th><th>Observed</th><th>Result</th><th>Detail coverage</th></tr></thead><tbody>{summary.recentScans.map(s=><tr key={s.id}><td>{s.project_name}</td><td>{s.source} #{s.scan_id}</td><td>{date(s.scanned_at)}</td><td>{s.source_status}</td><td>{s.details_complete?'Verified':'Incomplete / unavailable history'}</td></tr>)}</tbody></table>}</section>
 </>}
 {isCompliance&&<ComplianceOverview data={summary.compliance} query={query} change={change} chooseMapping={chooseMapping} inspect={inspect} Chart={Chart}/>}
 {!isReports&&listing&&<section className="card p-4 overflow-auto"><h2 className="font-semibold mb-3">Unified findings ({listing.total})</h2><p className="text-xs mb-3">Includes security hotspots and unclassified SAST findings requiring review; code smells and bugs are excluded. Accepted risk remains unresolved.</p><table className="gh-table"><thead><tr><th>Vulnerability</th><th>Project</th><th>Severity</th><th>Source</th><th>Location</th><th>Status</th><th>Detected</th><th>Action</th></tr></thead><tbody>{listing.findings.length?listing.findings.map(f=><tr key={f.id}><td>{f.title}<small className="block text-[var(--text-secondary)]">{f.identity}</small></td><td>{f.project_name}</td><td><SeverityBadge severity={f.severity}/></td><td>{f.source}</td><td className="max-w-xs break-words">{f.location||'Not supplied'}</td><td>{f.status}</td><td>{date(f.first_seen)}</td><td><button className="secondary-btn" onClick={()=>inspect(f.id)}>View details</button></td></tr>):<tr><td colSpan={8} className="p-8 text-center">No findings match this selection. Missing scans do not establish security.</td></tr>}</tbody></table>
 <div className="flex gap-3 items-center mt-3"><button className="secondary-btn" disabled={page<=1} onClick={()=>{const p=new URLSearchParams(params);p.set('page',String(page-1));setParams(p);}}>Previous</button><span>Page {listing.page} of {Math.max(1,Math.ceil(listing.total/listing.pageSize))}</span><button className="secondary-btn" disabled={page*listing.pageSize>=listing.total} onClick={()=>{const p=new URLSearchParams(params);p.set('page',String(page+1));setParams(p);}}>Next</button><label>Rows<select className="input ml-2" value={params.get('pageSize')||'25'} onChange={e=>change('pageSize',e.target.value)}>{[10,25,50,100].map(n=><option key={n}>{n}</option>)}</select></label></div></section>}
 </>}
 {detailId&&<div className="fixed inset-0 z-50 bg-black/70 flex items-start justify-center overflow-y-auto p-4" onClick={e=>{if(e.target===e.currentTarget){setDetail(null);setDetailId(null);}}}><section role="dialog" aria-modal="true" aria-labelledby="finding-title" tabIndex={-1} ref={detailRef} className="card p-6 w-full max-w-3xl space-y-4 my-6"><button autoFocus className="secondary-btn float-right" onClick={()=>{setDetail(null);setDetailId(null);}}>Close</button><h2 id="finding-title" className="text-xl font-semibold">Finding details</h2>{detailLoading&&<p role="status">Loading finding…</p>}{detailError&&<p role="alert" className="text-red-400">{detailError}</p>}{detail&&<>
 <h3 className="font-semibold">{detail.finding.title}</h3><p><SeverityBadge severity={detail.finding.severity}/> {detail.finding.status} · {detail.finding.classification}</p><p>{detail.finding.description}</p><p className="break-all">Location: {detail.finding.location||'Not supplied'}</p><p>Remediation: {detail.finding.remediation}</p><p>References: {detail.finding.references_json.join(', ')||'None supplied'}</p><h3 className="font-semibold">Compliance evidence</h3>{detail.finding.mappings.length?detail.finding.mappings.map(m=><p key={`${m.framework}-${m.id}`}>{m.framework} {m.version} {m.id} — {m.basis} (rules: {(m.mappingRules||[]).join(', ')||'legacy mapping'}) <a className="text-[var(--accent-blue)]" href={m.reference} target="_blank" rel="noreferrer">Reference</a></p>):<p>Not mapped: no supported rule or explicit reference.</p>}
 <h3 className="font-semibold">Scan observations</h3>{detail.observations.map((o,i)=><div key={i} className="border-b border-[var(--border-subtle)] py-2"><p>{o.source} scan #{o.scan_id} · {date(o.observed_at)} · {o.details_complete?'Details verified':'Incomplete coverage'}</p><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(o.evidence,null,2)}</pre></div>)}
 <h3 className="font-semibold">Owner review</h3><label>Status<select aria-label="Finding status" className="input block" value={status} onChange={e=>setStatus(e.target.value)}>{statuses.map(s=><option key={s}>{s}</option>)}</select></label><label className="block">Review reason<textarea aria-label="Review reason" className="input block w-full" maxLength={1000} value={reason} onChange={e=>setReason(e.target.value)}/></label><button className="primary-btn" disabled={saving||reason.trim().length<3} onClick={save}>{saving?'Saving…':'Save reviewed status'}</button>
 <h3 className="font-semibold">Status history</h3>{detail.history.length?detail.history.map((h,i)=><p key={i}>{date(h.changed_at)}: {h.old_status} → {h.new_status}. {h.reason}</p>):<p>No manual reviews recorded.</p>}
 </>}</section></div>}
 </div>;
}
