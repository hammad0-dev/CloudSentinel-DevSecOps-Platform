import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft, Loader2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import api from "../lib/api";
import { imageScanView } from "../utils/executionScan";

// Container image scan results (Trivy image) saved with one pipeline execution; opened from the execution report.
export default function ImageScanResults() {
  const { id } = useParams(), [params] = useSearchParams(), executionId = params.get("executionId");
  const [report, setReport] = useState(null), [error, setError] = useState(""), [loading, setLoading] = useState(!!executionId);
  useEffect(() => {
    if (!executionId) return undefined;
    let active = true; setLoading(true); setError("");
    api.get(`/reports/projects/${id}/executions/${executionId}`)
      .then((r) => active && setReport(r.data))
      .catch((e) => active && setError(e.response?.status === 404 ? "This execution is not available for the selected project." : e.response?.data?.error || "Unable to load the image scan."))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [id, executionId]);
  const back = executionId ? `/projects/${id}/executions/${executionId}/report` : "/cicd";
  if (!executionId) return <div className="card p-8">Open container image results from an execution report. <Link className="text-[var(--accent-green)]" to="/cicd">Pipeline history</Link></div>;
  if (loading) return <div className="card p-8 flex gap-3"><Loader2 className="animate-spin" />Loading image scan…</div>;
  if (error) return <div className="card p-8">{error} <Link className="text-[var(--accent-green)]" to={back}>Back</Link></div>;
  const v = imageScanView(report);
  return (
    <div className="space-y-6">
      <PageHeader title="Container image scan" subtitle={`Project #${id} · Execution #${executionId}`} actions={<Link className="secondary-btn inline-flex gap-1" to={back}><ArrowLeft size={14} />Execution report</Link>} />
      {!v.scan ? <div className="card p-6">No image scan is linked to this execution.</div> : <>
        <div className="card p-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4 text-sm">
          <div><p className="text-xs text-[var(--text-tertiary)]">Image</p><p className="font-mono break-all">{v.imageTag || "—"}</p></div>
          <div><p className="text-xs text-[var(--text-tertiary)]">Scan status</p><p>{v.scan.status}{v.result ? ` · gate ${v.result}` : ""}</p></div>
          <div><p className="text-xs text-[var(--text-tertiary)]">Vulnerabilities</p><p>{v.items.length} ({v.fixable} with a fix available)</p></div>
          <div><p className="text-xs text-[var(--text-tertiary)]">Gate rule</p><p>{v.rule?.blocks || "—"}</p></div>
          {v.scan.failure_reason && <p className="sm:col-span-2 xl:col-span-4 text-[var(--accent-red)]">{v.scan.failure_reason}</p>}
        </div>
        <div className="card overflow-auto">
          {!v.items.length ? <p className="p-4 text-sm text-[var(--text-secondary)]">{v.scan.status === "COMPLETED" ? "No findings" : `Scan status: ${v.scan.status}.`}</p> : (
            <table className="w-full min-w-[720px] text-sm">
              <thead><tr className="text-left text-[var(--text-tertiary)] border-b border-[var(--border-subtle)]"><th className="p-3">Severity</th><th className="p-3">Vulnerability</th><th className="p-3">Package</th><th className="p-3">Installed</th><th className="p-3">Fixed in</th><th className="p-3">Title</th></tr></thead>
              <tbody>{v.items.map((x, i) => <tr key={`${x.vulnerability_id}-${x.package_name}-${i}`} className="border-b border-[var(--border-subtle)]"><td className="p-3"><SeverityBadge severity={x.severity} /></td><td className="p-3 font-mono text-xs">{x.vulnerability_id}</td><td className="p-3">{x.package_name}</td><td className="p-3 font-mono text-xs">{x.installed_version}</td><td className="p-3 font-mono text-xs">{x.fixed_version || "No fix yet"}</td><td className="p-3 text-[var(--text-secondary)]">{x.title || "—"}</td></tr>)}</tbody>
            </table>)}
        </div>
      </>}
    </div>
  );
}
