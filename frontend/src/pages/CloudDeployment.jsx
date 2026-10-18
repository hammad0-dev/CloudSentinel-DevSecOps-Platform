import StaticDeploymentPanel from "../components/StaticDeploymentPanel";
import InfrastructureWorkflow from "../components/InfrastructureWorkflow";
import { routeTableLabel } from "../lib/cloudRoutes";
import { useEffect, useState } from "react";
import PageHeader from "../components/PageHeader";
import api from "../lib/api";

export function NetworkPanel({ network }) {
  if (!network) return <div className="card p-5">Select a project to read its AWS network.</div>;
  if (network.status !== "observed") return <div className="card p-5">AWS: {network.status === "not_configured" ? "Not configured" : "Not connected"}. {network.reason}</div>;
  return <section className="card p-5 space-y-4">
    <h3 className="font-bold">Project {network.projectId} AWS Network</h3>
    <p>Read-only AWS snapshot • {network.region} • {network.environment}</p>
    <p className="text-sm text-[#94a3b8]">Observed {new Date(network.observedAt).toLocaleString()}. This is a point-in-time read, not continuous monitoring or a Terraform apply record.</p>
    <p>Account: {network.account} | VPC: {network.vpc.id} | {network.vpc.cidr} | {network.vpc.state}</p>
    <div className="overflow-auto"><table className="w-full text-base [&_td]:px-4 [&_td]:py-4 [&_td]:align-top [&_th]:px-4 [&_th]:py-3 [&_tr]:border-b [&_tr]:border-[#1e2d4a]"><thead><tr className="text-left text-[#94a3b8]"><th className="p-2">Resource</th><th className="p-2">ID</th><th className="p-2">Observed configuration/status</th></tr></thead>
      <tbody>
        {network.subnets.map(s=><tr key={s.id}><td className="p-2">{s.tier} subnet</td><td className="p-2 font-mono whitespace-nowrap">{s.id}</td><td className="p-2">{s.cidr} • {s.zone} • {s.state} • Auto public IP: {s.publicIpOnLaunch ? "Enabled" : "Disabled"}</td></tr>)}
        {network.internetGateways.map(g=><tr key={g.id}><td className="p-2">Internet gateway</td><td className="p-2 font-mono whitespace-nowrap">{g.id}</td><td className="p-2">Attached to this VPC</td></tr>)}
        {network.routeTables.map(r=><tr key={r.id}><td className="p-2">{routeTableLabel(r,network)}</td><td className="p-2 font-mono whitespace-nowrap">{r.id}</td><td className="p-2">{r.routes.map(x=>`${x.destination} → ${x.target} (${x.state})`).join("; ")}<br/>Subnet associations: {r.subnets.join(", ") || "None"}</td></tr>)}
        {network.securityGroups.map(s=><tr key={s.id}><td className="p-2 max-w-xs break-words">Security group<br/><span className="text-sm text-slate-400 break-all">{s.name}</span></td><td className="p-2 font-mono whitespace-nowrap">{s.id}</td><td className="p-2">{s.status}</td></tr>)}
        {network.flowLogs.map(f=><tr key={f.id}><td className="p-2">Flow Log</td><td className="p-2 font-mono whitespace-nowrap">{f.id}</td><td className="p-2">{f.status} • Delivery: {f.delivery} • {f.trafficType} • {f.destinationType}</td></tr>)}
      </tbody></table></div>
    {!network.flowLogs.length && <p>Flow Logs: Not configured.</p>}
    <p className="text-sm text-[#94a3b8]">{network.findingsStatus}</p>
  </section>;
}
export default function CloudDeployment() {
  const [projects,setProjects]=useState([]),[project,setProject]=useState(""),[network,setNetwork]=useState(null),[loading,setLoading]=useState(false),[error,setError]=useState("");
  useEffect(()=>{let active=true;api.get('/projects').then(r=>{if(active)setProjects(r.data.projects||[]);}).catch(()=>{if(active)setError('Unable to load authorized projects.');});return()=>{active=false;};},[]);
  useEffect(()=>{let active=true;setNetwork(null);setLoading(false);if(!project)return()=>{active=false;};setLoading(true);setError("");api.get(`/cloud/projects/${project}/network`,{timeout:30000}).then(r=>{if(active)setNetwork(r.data);}).catch(()=>{if(active)setError('AWS inventory unavailable. No live status verified.');}).finally(()=>{if(active)setLoading(false);});return()=>{active=false;};},[project]);
  return <div className="space-y-6">
    <PageHeader title="Cloud Security Posture" subtitle="Project-scoped cloud network inventory"/>
    <div className="grid md:grid-cols-3 gap-4"><div className="card p-4">AWS: {loading ? "Reading…" : network?.status === "observed" ? "Snapshot available" : network?.status === "not_configured" ? "Not configured" : "Not connected"}</div><div className="card p-4">GCP: Not connected</div><div className="card p-4">Azure: Not connected</div></div>
    <label className="block">Project <select className="ml-3 bg-[#0b1220] border border-[#1e2d4a] rounded p-2" value={project} onChange={e=>setProject(e.target.value)}><option value="">Select project</option>{projects.map(p=><option key={p.id} value={p.id}>{p.name} (#{p.id})</option>)}</select></label>
    {error && <p role="alert">{error}</p>}
    {loading ? <p role="status">Reading AWS inventory…</p> : <NetworkPanel network={network}/>}
    {project && <StaticDeploymentPanel key={`static-${project}`} projectId={project}/>}
    {project && <InfrastructureWorkflow key={project} projectId={project}/>}
    <div className="card p-5"><h3 className="font-bold">Security findings</h3><p>No cloud security assessment is connected. No AWS, GCP or Azure findings are asserted.</p></div>
  </div>;
}
