import {useEffect,useState} from 'react';
import api from '../lib/api';
export function DiagnosticCard({diagnostic:d}){
 return <section className="card p-5 space-y-3" aria-label="Historical isolated diagnostic">
  <h2 className="font-semibold">{d.label}</h2>
  <p className="text-sm">{d.target}</p>
  <p className="text-sm">Diagnostic {d.diagnosticId} · {d.date} · {d.totalFindings} finding instances</p>
  <p className="text-sm">Diagnostic: {d.diagnosticStatus} · Artifact integrity: {d.integrity} · Evidence: {d.evidenceStatus} · Production acceptance: {d.productionAcceptance}</p>
  <p className="text-sm">Configured limit: {d.configuredRequestsPerSecond} requests/sec. Independently measured rate enforcement: {d.measuredRateEnforcement}. These results do not change execution #37; its Active DAST remains SKIPPED.</p>
  <div className="overflow-auto"><table className="w-full text-sm"><thead><tr><th className="text-left p-2">Finding / source</th><th>CWE</th><th>Severity</th><th>ZAP rule</th><th>Fixture endpoint</th><th>Instances</th></tr></thead><tbody>{d.findings.map(f=><tr key={f.ruleId} className="border-t"><td className="p-2">{f.name} ({f.source})</td><td>{f.cwe||'Not specified'}</td><td>{f.severity}</td><td>{f.ruleId}</td><td>{f.endpoints.join(', ')}</td><td>{f.instanceCount}</td></tr>)}</tbody></table></div>
  <details><summary>Report integrity hashes</summary><p className="break-all text-xs">Original report SHA-256: {d.originalReportSha256}</p><p className="break-all text-xs">Retained sanitized report SHA-256: {d.storedReportSha256}</p></details>
 </section>;
}
export default function HistoricalDastDiagnostics({projectId}){
 const [state,setState]=useState({items:[],error:null});
 useEffect(()=>{let live=true;setState({items:[],error:null});if(projectId)api.get(`/dast/diagnostics/${projectId}`).then(r=>{if(live)setState({items:r.data.diagnostics,error:null});}).catch(()=>{if(live)setState({items:[],error:'Historical diagnostic evidence is unavailable or could not be verified.'});});return()=>{live=false;};},[projectId]);
 if(state.error)return <div className="card p-4" role="alert">{state.error}</div>;
 return <>{state.items.map(d=><DiagnosticCard key={d.diagnosticId} diagnostic={d}/>)}</>;
}
