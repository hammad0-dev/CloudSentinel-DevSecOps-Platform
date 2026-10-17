import { Link, useLocation, useParams, useSearchParams } from "react-router-dom";

export default function ExecutionScanNotice() {
  const [params] = useSearchParams();
  const { id } = useParams();
  const { pathname } = useLocation();
  const executionId = params.get("executionId");
  const projectId = params.get("projectId") || id;
  if (!executionId || !projectId) return null;
  return <div className="card p-4 mb-6 flex flex-wrap items-center justify-between gap-3 text-sm">
    <span>Saved results for execution #{executionId}</span>
    <div className="flex gap-4">
      <Link className="text-[var(--accent-green)]" to={`/projects/${projectId}/executions/${executionId}/report`}>Back to execution report</Link>
      <Link className="text-[var(--accent-green)]" to={`${pathname}?projectId=${projectId}`}>View latest results</Link>
    </div>
  </div>;
}
