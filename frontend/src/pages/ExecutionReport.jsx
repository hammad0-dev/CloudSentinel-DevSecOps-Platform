import { getExecutionResultsLink } from "../utils/executionScan";
import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AlertTriangle, ArrowLeft, CheckCircle, Download, ExternalLink, FileCode2, Loader2, Printer, XCircle } from "lucide-react";
import PageHeader from "../components/PageHeader";
import api from "../lib/api";
import { SEVERITIES, buildPrintableExecutionReport, downloadReport, formatDuration, getCleanPackagesText, getDetailedFindingCount, getDetailedFindingGroups, getFindingDetails, getFindingIdentifier, getFindingLocation, getKubernetesSummary, getSastStatusText, getSastSummaryCount, getStageRows, normalizeSeverity, shortCommit } from "../utils/executionReport";

const display = (v) => (v === null || v === undefined || v === "" ? "—" : String(v));
const safeUrl = (v) => { try { const u = new URL(v); return ["http:", "https:"].includes(u.protocol) ? u.href : null; } catch { return null; } };
const severityClass = (s) => ({ CRITICAL: "text-red-300 bg-red-500/15", HIGH: "text-orange-300 bg-orange-500/15", MEDIUM: "text-yellow-300 bg-yellow-500/15", LOW: "text-blue-300 bg-blue-500/15", INFORMATIONAL: "text-cyan-300 bg-cyan-500/15", UNKNOWN: "text-gray-300 bg-gray-500/15" }[normalizeSeverity(s)]);
const resultClass = (r) => ({ PASSED: "text-green-400", BLOCKED: "text-red-400", FAILED: "text-red-400", RUNNING: "text-yellow-300" }[r] || "text-[var(--text-secondary)]");
const SCAN_KEYS = ["sast", "dependency", "iac", "image", "dast"];

function Findings({ name, items, resultsLink, scan, footnote }) {
  return (
    <div className="card overflow-auto">
      <div className="p-4 border-b border-[var(--border-subtle)] flex justify-between">
        <h3 className="font-semibold">{name}</h3>
        <div className="flex flex-wrap items-center justify-end gap-4">
          <span className="text-sm text-[var(--text-secondary)]">{items.length} linked findings</span>
          {resultsLink && <Link to={resultsLink} className="text-sm text-[var(--accent-green)] inline-flex items-center gap-1">View results<ExternalLink size={14} /></Link>}
        </div>
      </div>
      {!items.length ? (
        <p className="p-4 text-sm text-[var(--text-secondary)]">{scan?.status === "COMPLETED" ? "No findings" : scan ? `Scan status: ${scan.status}. No linked findings available.` : "This stage has no scan linked to this execution."}</p>
      ) : (
        <table className="w-full min-w-[680px] text-sm">
          <thead><tr className="text-left text-[var(--text-tertiary)] border-b border-[var(--border-subtle)]"><th className="p-3">Severity</th><th className="p-3">Rule / CVE</th><th className="p-3">Package, path, or endpoint</th><th className="p-3">Details</th></tr></thead>
          <tbody>{items.map((f, i) => (
            <tr key={`${name}-${getFindingIdentifier(f)}-${i}`} className="border-b border-[var(--border-subtle)]">
              <td className="p-3"><span className={`px-2 py-1 rounded text-xs ${severityClass(f.severity)}`}>{normalizeSeverity(f.severity)}</span></td>
              <td className="p-3 font-mono text-xs">{display(getFindingIdentifier(f))}</td>
              <td className="p-3 break-all">{display(getFindingLocation(f))}</td>
              <td className="p-3 text-[var(--text-secondary)]">{getFindingDetails(f) || "No advisory text in the scanner output"}</td>
            </tr>))}
          </tbody>
        </table>
      )}
      {footnote && <p className="px-4 pb-4 pt-2 text-xs text-[var(--text-tertiary)]">{footnote}</p>}
    </div>
  );
}

function Field({ label, children, mono }) {
  return <div><p className="text-xs text-[var(--text-tertiary)]">{label}</p><p className={`text-sm break-all ${mono ? "font-mono" : ""}`}>{children}</p></div>;
}

export default function ExecutionReport() {
  const { projectId, executionId } = useParams();
  const [report, setReport] = useState(null), [live, setLive] = useState(null), [loading, setLoading] = useState(true), [error, setError] = useState(null);
  useEffect(() => {
    let active = true;
    setLoading(true); setError(null); setLive(null);
    api.get(`/reports/projects/${projectId}/executions/${executionId}`)
      .then((r) => active && setReport(r.data))
      .catch((e) => { if (active) { const s = e.response?.status; setError(s === 404 ? "This execution is not available for the selected project." : s === 401 ? "Your session has expired. Please sign in again." : e.response?.data?.error || "Unable to load the execution report."); } })
      .finally(() => active && setLoading(false));
    // Live Kyverno compliance for the project namespace; labelled as live, not as execution evidence.
    api.get(`/kubernetes/projects/${projectId}/policies`)
      .then((r) => active && setLive({ status: r.data?.status, reason: r.data?.reason, compliance: r.data?.compliance || null }))
      .catch(() => active && setLive({ status: "unavailable", reason: "Kubernetes policy reports could not be read" }));
    return () => { active = false; };
  }, [projectId, executionId]);
  const merged = useMemo(() => (report ? { ...report, kubernetes: { ...(report.kubernetes || {}), live } } : null), [report, live]);
  const groups = useMemo(() => getDetailedFindingGroups(merged), [merged]);
  const detailed = getDetailedFindingCount(merged), sast = getSastSummaryCount(merged);

  if (loading) return <div className="card p-8 flex gap-3"><Loader2 className="animate-spin" />Loading execution report…</div>;
  if (error) return <div className="card p-8 text-center"><AlertTriangle className="mx-auto text-[var(--accent-red)]" /><h2 className="mt-3 font-semibold">Report unavailable</h2><p className="mt-2 text-[var(--text-secondary)]">{error}</p><Link className="secondary-btn inline-flex mt-5" to="/cicd">Return to pipeline history</Link></div>;
  if (!merged) return <div className="card p-8">No report data is available.</div>;

  const { execution, deployment, scans = {}, counts = {}, gates = {}, source = {}, timing = {}, gateRules = {} } = merged;
  const meta = merged.report || {};
  const staging = safeUrl(deployment?.staging_url);
  const gatesList = [["Static security", gates.staticPassed], ["Image security", gates.imagePassed], ["Deployment", gates.deploymentSucceeded], ["DAST", gates.dastCompleted]];
  const json = () => downloadReport(JSON.stringify(merged, null, 2), "application/json", `cloudsentinel-execution-${executionId}.json`);
  const html = () => downloadReport(buildPrintableExecutionReport(merged), "text/html", `cloudsentinel-execution-${executionId}.html`);
  const stageRows = getStageRows(merged), clean = getCleanPackagesText(merged);

  return (
    <div className="space-y-6">
      <PageHeader title={`Execution Report #${execution.id}`} subtitle={`${execution.name || "Project"} · ${execution.status}`} actions={
        <div className="flex flex-wrap gap-2">
          <Link className="secondary-btn inline-flex gap-1" to="/cicd"><ArrowLeft size={14} />Pipeline history</Link>
          <button className="secondary-btn inline-flex gap-1" onClick={json}><FileCode2 size={14} />JSON</button>
          <button className="secondary-btn inline-flex gap-1" onClick={html}><Download size={14} />HTML</button>
          <button className="primary-btn inline-flex gap-1" onClick={() => window.print()}><Printer size={14} />Print</button>
        </div>} />

      <div className="card p-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Field label="Repository">{source.repository ? <a className="text-[var(--accent-green)]" href={safeUrl(source.repository) || undefined} target="_blank" rel="noreferrer">{source.repository}</a> : "—"}</Field>
        <Field label="Branch">{display(source.branch)}</Field>
        <Field label="Commit" mono>{source.commit ? <span title={source.commit}>{shortCommit(source.commit)}</span> : <span className="font-sans text-[var(--text-secondary)]">{source.note || "Not recorded"}</span>}</Field>
        <Field label="Commit message">{display(source.message)}</Field>
        <Field label="Status"><b>{execution.status}</b></Field>
        <Field label="Trigger">{display(execution.triggered_by)}</Field>
        <Field label="Started">{execution.started_at ? new Date(execution.started_at).toLocaleString() : "—"}</Field>
        <Field label="Duration">{execution.completed_at ? formatDuration(timing.durationMs) : "In progress"}</Field>
        <Field label="Report ID" mono>{display(meta.id)}</Field>
        <Field label="Generated at">{meta.generatedAt ? new Date(meta.generatedAt).toLocaleString() : "—"}</Field>
        {execution.failure_reason && <div className="sm:col-span-2 xl:col-span-4 text-[var(--accent-red)] text-sm">{execution.failure_reason}</div>}
      </div>

      <div className="card overflow-auto">
        <h2 className="font-semibold p-4 border-b border-[var(--border-subtle)]">Pipeline stages</h2>
        {stageRows.length ? (
          <table className="w-full min-w-[680px] text-sm">
            <thead><tr className="text-left text-[var(--text-tertiary)] border-b border-[var(--border-subtle)]"><th className="p-3">Stage</th><th className="p-3">Result</th><th className="p-3">Duration</th><th className="p-3">Engine and version</th></tr></thead>
            <tbody>{stageRows.map((s) => (
              <tr key={s.stage} className="border-b border-[var(--border-subtle)]">
                <td className="p-3">{s.stage}</td>
                <td className={`p-3 font-semibold ${resultClass(s.result)}`}><span className="inline-flex items-center gap-1">{s.result === "PASSED" ? <CheckCircle size={13} /> : ["BLOCKED", "FAILED"].includes(s.result) ? <XCircle size={13} /> : null}{s.result.replace("_", " ")}</span></td>
                <td className="p-3">{s.duration}</td>
                <td className="p-3 text-[var(--text-secondary)]">{s.engine}</td>
              </tr>))}
            </tbody>
          </table>
        ) : <p className="p-4 text-[var(--text-secondary)]">No stage records.</p>}
        <p className="px-4 py-2 text-xs text-[var(--text-tertiary)]">Deploy has no stored start time; its duration runs from the end of the previous stage.</p>
      </div>

      <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-4">{gatesList.map(([name, passed]) => <div className="card p-4" key={name}><p className="text-sm text-[var(--text-secondary)]">{name} gate</p><p className={`mt-2 font-semibold ${passed === true ? "text-green-400" : passed === false ? "text-red-400" : "text-[var(--text-secondary)]"}`}>{passed === true ? "Passed" : passed === false ? "Not passed" : "Not evaluated"}</p></div>)}</div>

      <div className="card overflow-auto">
        <div className="p-4 border-b border-[var(--border-subtle)]"><h2 className="font-semibold">Gate rules in force</h2><p className="text-xs text-[var(--text-tertiary)] mt-1">{gateRules.note}</p></div>
        <table className="w-full min-w-[680px] text-sm">
          <thead><tr className="text-left text-[var(--text-tertiary)] border-b border-[var(--border-subtle)]"><th className="p-3">Stage</th><th className="p-3">Blocks</th><th className="p-3">Why</th></tr></thead>
          <tbody>{(gateRules.rules || []).map((r) => <tr key={r.stage} className="border-b border-[var(--border-subtle)]"><td className="p-3">{r.stage}</td><td className={`p-3 ${r.valid === false ? "text-red-400" : ""}`}>{r.blocks}</td><td className="p-3 text-[var(--text-secondary)]">{r.why}</td></tr>)}</tbody>
        </table>
      </div>

      <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="card p-4"><p className="text-sm text-[var(--text-secondary)]">Execution-linked detailed findings</p><p className="text-3xl font-bold mt-2">{detailed}</p><p className="text-xs text-[var(--text-tertiary)] mt-1">Includes linked SAST, Dependency, IaC, image, and DAST findings.</p></div>
        <div className="card p-4"><p className="text-sm text-[var(--text-secondary)]">SAST summary findings</p><p className="text-3xl font-bold mt-2">{sast}</p><p className="text-xs text-[var(--accent-yellow)] mt-1">Included in the detailed total; shown separately for context.</p></div>
        {SEVERITIES.slice(0, 2).map((s) => <div className="card p-4" key={s}><p className="text-sm text-[var(--text-secondary)]">{s} detailed</p><p className="text-3xl font-bold mt-2">{Number(counts.bySeverity?.[s] || 0)}</p></div>)}
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="card p-5">
          <h2 className="font-semibold mb-3">Deployment and image identity</h2>
          <p className="text-sm text-[var(--text-secondary)]">Deployment status</p><p>{display(deployment?.status)}</p>
          <p className="text-sm text-[var(--text-secondary)] mt-3">Image</p><p className="font-mono text-xs break-all">{display(deployment?.image_tag || scans.image?.image_tag)}</p>
          <p className="text-sm text-[var(--text-secondary)] mt-3">DAST scan mode</p><p>{scans.dast?.scan_mode || "Legacy / unknown"}</p>
          <p className="text-sm text-[var(--text-secondary)] mt-3">Staging URL</p>
          {staging ? <a href={staging} target="_blank" rel="noreferrer" className="text-[var(--accent-green)] inline-flex gap-1 break-all">{staging}<ExternalLink size={13} /></a> : <p>—</p>}
        </div>
        <div className="card p-5">
          <h2 className="font-semibold mb-3">Kubernetes and compliance</h2>
          <ul className="space-y-2 text-sm">{getKubernetesSummary(merged).map((l) => <li key={l}>{l}</li>)}</ul>
        </div>
      </div>

      <div className="card p-5 border border-[var(--accent-yellow)]/30"><h2 className="font-semibold">SAST execution details</h2><p className="text-sm text-[var(--text-secondary)] mt-2">{getSastStatusText(merged)}</p></div>

      <div className="space-y-4">
        <h2 className="font-semibold">Execution-linked detailed findings</h2>
        {groups.map(([name, items], index) => <Findings key={name} name={name} items={items} scan={scans[SCAN_KEYS[index]]} resultsLink={getExecutionResultsLink(name, projectId, executionId)} footnote={name === "Dependency / SBOM" ? clean : ""} />)}
      </div>
    </div>
  );
}
