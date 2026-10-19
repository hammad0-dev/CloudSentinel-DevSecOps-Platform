import {useEffect, useState} from 'react';
import {useSearchParams} from 'react-router-dom';
import {Download, FileJson} from 'lucide-react';
import api from '../lib/api';

const sources=['SAST','DEPENDENCY','IAC','IMAGE','DAST','ACTIVE_DAST'];
const sourceName={DEPENDENCY:'Dependencies',IAC:'IaC',IMAGE:'Image',ACTIVE_DAST:'Active DAST'};
const percentage=value=>value==null?'Not assessed':`${value}%`;
function saveBlob(blob,name){const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function FrameworkCard({title,value,description,note}){
 return <section className="card p-4 space-y-2"><h2 className="font-semibold">{title}</h2><p className="text-sm text-[var(--text-secondary)]">{description}</p><div className="h-2 rounded-full bg-[var(--bg-canvas)] border border-[var(--border-subtle)] overflow-hidden"><div className="h-full bg-emerald-400 rounded-full" style={{width:`${value??0}%`}}/></div><div className="flex justify-between text-sm"><span>{percentage(value)}</span><span className="text-[var(--text-secondary)]">{note}</span></div></section>;
}
function Controls({title,rows,framework}){
 return <section className="card p-4 overflow-x-auto"><h2 className="font-semibold mb-3">{title}</h2><table className="gh-table w-full"><thead><tr>{['Control ID','Framework','Description','Findings','Critical','High'].map(x=><th key={x}>{x}</th>)}</tr></thead><tbody>{rows.length?rows.map(row=><tr key={row.id}><td>{row.id}</td><td>{framework}</td><td>{row.name}</td><td>{row.findings}</td><td>{row.bySeverity?.CRITICAL||0}</td><td>{row.bySeverity?.HIGH||0}</td></tr>):<tr><td colSpan={6} className="text-center py-5 text-[var(--text-secondary)]">No {title.includes('OWASP')?'OWASP':'CIS'}-mapped findings</td></tr>}</tbody></table></section>;
}
export default function ComplianceDashboard(){
 const [params,setParams]=useSearchParams();
 const project=params.get('project')||'',version=params.get('owaspVersion')||'2021';
 const [projects,setProjects]=useState([]),[data,setData]=useState(null),[error,setError]=useState(''),[loading,setLoading]=useState(true),[exporting,setExporting]=useState(false),[revision,setRevision]=useState(0);
 const query=new URLSearchParams({...(project?{project}:{}),owaspVersion:version}).toString();
 useEffect(()=>{
  const controller=new AbortController();let active=true;
  async function load(){setLoading(true);setError('');try{
   await api.post('/governance/sync',{}, {signal:controller.signal});
   const [p,s]=await Promise.all([api.get('/projects',{signal:controller.signal}),api.get(`/governance/summary?${query}`,{signal:controller.signal})]);
   if(active){setProjects(p.data.projects||[]);setData(s.data);}
  }catch(e){if(active&&!controller.signal.aborted){setError(e.response?.data?.error||'Unable to load pipeline compliance results');setData(null);}}finally{if(active)setLoading(false);}}
  load();const timer=setInterval(load,30000);return()=>{active=false;controller.abort();clearInterval(timer);};
 },[query,revision]);
 function change(key,value){setData(null);setLoading(true);const next=new URLSearchParams(params);if(value)next.set(key,value);else next.delete(key);setParams(next);}
 async function report(){setExporting(true);try{const r=await api.get(`/governance/export/compliance?${query}`,{responseType:'blob'});saveBlob(r.data,'cloudsentinel-compliance.pdf');}catch{setError('Unable to export report. Please retry.');}finally{setExporting(false);}}
 const compliance=data?.compliance,metrics=compliance?.metrics||{};
 const mappedOwasp=compliance?.owasp.filter(c=>c.findings>0)||[],mappedCis=compliance?.cisControls?.filter(c=>c.findings>0)||[];
 const verifiedCompliance=compliance?.overall?.passRate??null;
 const owaspMappingCoverage=compliance?.matching?.owasp?.percentage??0;
 return <div className="space-y-5 min-w-0">
 <header className="flex flex-wrap items-center justify-between gap-4"><div><h1 className="text-2xl font-semibold">Compliance Dashboard</h1><p className="text-sm text-[var(--text-secondary)] mt-1">OWASP Top 10 and CIS benchmark mapping from combined pipeline results</p></div><div className="flex flex-wrap items-center gap-2"><select aria-label="Project" className="input min-w-48" value={project} onChange={e=>change('project',e.target.value)}><option value="">All projects</option>{projects.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select><button className="primary-btn flex items-center gap-2" disabled={!data||exporting||loading} onClick={report}><Download size={16}/>{exporting?'Exporting…':'Export Readable Report'}</button><button className="secondary-btn flex items-center gap-2" disabled={!data||loading} onClick={()=>saveBlob(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),'cloudsentinel-compliance.json')}><FileJson size={16}/>Export JSON</button></div></header>
 {error&&<div className="card p-4 text-red-400" role="alert">{error} <button className="secondary-btn" onClick={()=>setRevision(r=>r+1)}>Retry</button></div>}
 {loading&&!data&&<p className="card p-6" role="status">Loading pipeline compliance results…</p>}
 {data&&compliance&&<>
 <section className="card p-6 text-center space-y-2"><p className="text-5xl font-bold">{percentage(verifiedCompliance)}</p><p className="text-[var(--text-secondary)]">Docker assessment pass rate · Failed controls: {compliance.overall?.FAIL||0} · Unmapped findings: {compliance.unmapped}</p><p className="text-xs text-[var(--text-secondary)]">Sources: {sources.map(source=>`${sourceName[source]||source} ${data.bySource.find(s=>s.name===source)?.value||0}`).join(' · ')}</p><p className="text-xs text-[var(--text-secondary)]">Assessed controls: {compliance.overall?.assessed||0}/{compliance.overall?.applicable||0} · Coverage: {percentage(compliance.overall?.coverage)} · Controls without assessment: {compliance.overall?.NOT_ASSESSED||0} · Errors: {compliance.overall?.ERROR||0}</p><p className="text-xs text-[var(--text-secondary)]">{compliance.overall?.methodology}</p></section>
 <div className="grid md:grid-cols-3 gap-4"><FrameworkCard title={compliance.version||'OWASP Top 10'} value={owaspMappingCoverage} description={`${compliance.matching?.owasp?.matched||0}/10 categories matched · ${compliance.owaspMetrics?.PASS||0} passed · ${compliance.owaspMetrics?.FAIL||0} failed · ${compliance.owaspMetrics?.NOT_ASSESSED||0} unassessed project-category slots`} note={`Category matching · pass rate: ${percentage(compliance.owaspMetrics?.passRate)}`}/><FrameworkCard title="CIS Controls" value={compliance.matching?.cisControls?.percentage??0} description={`${compliance.matching?.cisControls?.matched||0}/18 controls matched · Docker ${metrics.assessed||0}/${metrics.applicable||0} assessed project-control slots · ${metrics.PASS||0} passed · ${metrics.FAIL||0} failed · ${metrics.NOT_ASSESSED||0} unassessed`} note={`Control matching · Docker pass rate: ${percentage(metrics.passRate)}`}/></div>
 <Controls title="Mapped OWASP Controls" rows={mappedOwasp} framework={compliance.version}/>
 <Controls title="Mapped CIS Controls" rows={mappedCis} framework="CIS Controls v8 (associations)"/>
 <details className="card p-4"><summary className="cursor-pointer font-semibold">Pipeline evidence and assessment details</summary><p className="text-sm my-3">Results refresh every 30 seconds. Includes stored results from all scanning stages; deployment does not itself assess compliance. Missing scans and zero findings do not establish compliance.</p><div className="overflow-x-auto"><table className="gh-table w-full"><thead><tr><th>Project</th><th>Source</th><th>Scan</th><th>Result</th><th>Evidence</th></tr></thead><tbody>{data.recentScans.map(s=><tr key={s.id}><td>{s.project_name}</td><td>{sourceName[s.source]||s.source}</td><td>#{s.scan_id}</td><td>{s.source_status}</td><td>{s.details_complete?'Complete':'Incomplete'}</td></tr>)}</tbody></table></div><p className="text-sm mt-3">CIS assessment pass rate: {percentage(metrics.passRate)} ({metrics.PASS||0} passed / {metrics.assessed||0} assessed). {metrics.assessed?'':'No verified CIS checks are available. The adapter currently needs Dockerfile targets and explicit check outcomes; a completed scan with no targets does not assess this benchmark.'}</p><p className="text-sm mt-3">{metrics.methodology}</p><p className="text-sm mt-2">{compliance.limitations}</p><label className="block mt-3">OWASP version<select aria-label="OWASP version" className="input ml-2" value={version} onChange={e=>change('owaspVersion',e.target.value)}>{(compliance.availableOwaspVersions||['2021']).map(v=><option key={v}>{v}</option>)}</select></label><div className="overflow-x-auto mt-3"><table className="gh-table w-full"><thead><tr><th>Project</th><th>Control</th><th>Description</th><th>Assessment</th></tr></thead><tbody>{(compliance.projectControls||[]).map(c=><tr key={`${c.project_id}-${c.id}`}><td>{c.project_name}</td><td>{c.id}</td><td>{c.name}</td><td>{c.status}</td></tr>)}</tbody></table></div></details>
 </>}
 </div>;
}
