import { useState, useEffect, useCallback } from "react";
import PageHeader from "../components/PageHeader";
import api from "../lib/api";
import { ChevronDown, AlertTriangle, CheckCircle, Clock, XCircle, Play, ArrowRight, Server } from "lucide-react";

const PIPELINE_STAGES = ["SAST", "Dependency", "IaC", "Deploy", "DAST"];

export default function CICDPipeline() {
  const [projects, setProjects] = useState([]);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [pipelines, setPipelines] = useState([]);
  const [deployments, setDeployments] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.get("/projects")
      .then((res) => {
        const projs = res.data.projects || [];
        setProjects(projs);
        if (projs.length > 0) setSelectedProjectId(projs[0].id.toString());
      })
      .catch((err) => setError(err.message));
  }, []);

  const loadData = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError(null);
    try {
      const [pipeRes, depRes] = await Promise.all([
        api.get(`/projects/${selectedProjectId}/pipelines`),
        api.get(`/deployment/${selectedProjectId}/history`).catch(() => ({ data: { deployments: [] } })),
      ]);
      setPipelines(pipeRes.data.pipelines || []);
      setDeployments(depRes.data.deployments || []);
    } catch (err) {
      setError(err.response?.data?.error || "Failed to load pipeline data");
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  const selectedProject = projects.find(p => p.id.toString() === selectedProjectId);
  const latestPipeline = pipelines[0];
  const latestDeployment = deployments[0];

  const getStatusIcon = (status) => {
    switch (status) {
      case "COMPLETED": return <CheckCircle size={16} className="text-green-500" />;
      case "STAGE_FAILED": return <AlertTriangle size={16} className="text-red-500" />;
      case "ERROR": return <XCircle size={16} className="text-red-500" />;
      case "RUNNING":
      case "TRIGGERED": return <Play size={16} className="text-blue-500 animate-pulse" />;
      default: return <Clock size={16} className="text-gray-500" />;
    }
  };

  const getStatusBadge = (status) => {
    let classes = "px-2 py-0.5 rounded-full text-xs font-medium ";
    if (status === "COMPLETED") classes += "bg-green-500/10 text-green-400 border border-green-500/20";
    else if (status === "STAGE_FAILED") classes += "bg-red-500/10 text-red-400 border border-red-500/20";
    else if (status === "RUNNING") classes += "bg-blue-500/10 text-blue-400 border border-blue-500/20";
    else if (status === "TRIGGERED") classes += "bg-purple-500/10 text-purple-400 border border-purple-500/20";
    else if (status === "ERROR") classes += "bg-red-500/10 text-red-400 border border-red-500/20";
    else classes += "bg-gray-500/10 text-gray-400 border border-gray-500/20";
    return <span className={classes}>{status}</span>;
  };

  const renderWorkflowDiagram = () => {
    if (!latestPipeline) return (
      <div className="card p-6 mb-6">
        <h3 className="font-bold mb-4">Pipeline Workflow</h3>
        <div className="flex items-center gap-4 min-w-max pb-2 opacity-40">
          {PIPELINE_STAGES.map((s, i) => (
            <div key={s} className="flex items-center gap-4">
              <div className="w-36 h-24 rounded-lg border border-[#1e2d4a] bg-[#111827] flex flex-col items-center justify-center gap-2">
                <div className="font-semibold text-sm">{s}</div>
                <div className="text-xs text-[#64748b]">Pending</div>
              </div>
              {i < PIPELINE_STAGES.length - 1 && <ArrowRight className="text-[#334155]" size={20} />}
            </div>
          ))}
        </div>
      </div>
    );

    const completedArray = latestPipeline.stages_completed ? latestPipeline.stages_completed.split(", ") : [];

    const stages = PIPELINE_STAGES.map((stageName, index) => {
      let stageStatus = "Pending";
      const isCompleted = completedArray.includes(stageName);
      const isLastCompleted = completedArray[completedArray.length - 1] === stageName;
      const prevCompleted = index === 0 || completedArray.includes(PIPELINE_STAGES[index - 1]);

      if (isCompleted) {
        stageStatus = (isLastCompleted && latestPipeline.status === "STAGE_FAILED") ? "Failed" : "Passed";
      } else if (prevCompleted) {
        if (latestPipeline.status === "RUNNING") stageStatus = "Running";
        else if (latestPipeline.status === "ERROR") stageStatus = "Error";
        else if (latestPipeline.status === "STAGE_FAILED" || latestPipeline.status === "COMPLETED") stageStatus = "Skipped";
      } else {
        if (["STAGE_FAILED", "ERROR", "COMPLETED"].includes(latestPipeline.status)) stageStatus = "Skipped";
      }

      return { name: stageName, status: stageStatus };
    });

    // Find deployment info for the Deploy node
    const deployInfo = latestDeployment;

    return (
      <div className="card p-6 overflow-x-auto mb-6">
        <div className="flex items-start justify-between mb-4 flex-wrap gap-2">
          <h3 className="font-bold">Latest Pipeline Workflow (Execution #{latestPipeline.id})</h3>
          {deployInfo?.staging_url && deployInfo.status === "SUCCESS" && (
            <a
              href={deployInfo.staging_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20 transition-colors"
            >
              <Server size={12} />
              Live Staging: {deployInfo.staging_url}
            </a>
          )}
        </div>
        <div className="flex items-start gap-4 min-w-max pb-2">
          {stages.map((s, i) => (
            <div key={s.name} className="flex items-start gap-4">
              <div className={`w-36 rounded-lg border flex flex-col items-center justify-center gap-2 p-3 transition-all ${
                s.status === "Passed" ? "bg-green-500/10 border-green-500/30 shadow-[0_0_15px_rgba(34,197,94,0.1)]" :
                s.status === "Failed" ? "bg-red-500/10 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.2)]" :
                s.status === "Error" ? "bg-orange-500/10 border-orange-500/50" :
                s.status === "Running" ? "bg-blue-500/10 border-blue-500/50 shadow-[0_0_15px_rgba(59,130,246,0.2)]" :
                "bg-[#111827] border-[#1e2d4a] opacity-50"
              }`}>
                <div className="font-semibold text-sm">{s.name}</div>
                <div className={`text-xs uppercase tracking-wider font-bold flex items-center gap-1 ${
                  s.status === "Passed" ? "text-green-400" :
                  s.status === "Failed" || s.status === "Error" ? "text-red-400" :
                  s.status === "Running" ? "text-blue-400 animate-pulse" :
                  "text-[#64748b]"
                }`}>
                  {s.status === "Running" && <Play size={10} className="fill-current" />}
                  {s.status === "Passed" && <CheckCircle size={10} />}
                  {s.status === "Failed" && <AlertTriangle size={10} />}
                  {s.status}
                </div>
                {/* Deploy node: show generated badge */}
                {s.name === "Deploy" && s.status === "Passed" && deployInfo && (
                  <div className="flex flex-col items-center gap-0.5 mt-1">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${deployInfo.dockerfile_source === "generated" ? "bg-purple-500/20 text-purple-300" : "bg-gray-500/20 text-gray-400"}`}>
                      Dockerfile: {deployInfo.dockerfile_source}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${deployInfo.manifest_source === "generated" ? "bg-purple-500/20 text-purple-300" : "bg-gray-500/20 text-gray-400"}`}>
                      K8s: {deployInfo.manifest_source}
                    </span>
                  </div>
                )}
              </div>
              {i < stages.length - 1 && <ArrowRight className="text-[#334155] mt-8" size={20} />}
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <PageHeader
          title="CI/CD Pipeline History"
          subtitle="Automated pipeline: SAST → Dependency → IaC → Deploy (K8s) → DAST"
        />
        {projects.length > 0 && (
          <div className="relative w-full md:w-64">
            <select
              className="input w-full appearance-none pr-10"
              value={selectedProjectId}
              onChange={(e) => setSelectedProjectId(e.target.value)}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)] pointer-events-none" />
          </div>
        )}
      </div>

      {renderWorkflowDiagram()}

      <div className="card p-5 overflow-auto">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-bold">Recent Executions</h3>
          {selectedProject?.webhook_secret && (
            <span className="text-xs text-gray-400">
              Webhook Secret: <code className="bg-[#111827] px-1 py-0.5 rounded">{selectedProject.webhook_secret}</code>
            </span>
          )}
        </div>

        {error && <div className="text-red-400 mb-4">{error}</div>}

        {pipelines.length === 0 && !loading && (
          <p className="text-sm text-gray-400">No pipeline executions yet. Push to GitHub to trigger one.</p>
        )}

        {pipelines.length > 0 && (
          <table className="w-full text-sm text-left">
            <thead>
              <tr className="text-[#64748b] border-b border-[var(--border-subtle)]">
                <th className="pb-2 font-medium">Exec ID</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">Trigger</th>
                <th className="pb-2 font-medium">Stages Completed</th>
                <th className="pb-2 font-medium">Started At</th>
              </tr>
            </thead>
            <tbody>
              {pipelines.map((p) => (
                <tr key={p.id} className="border-b border-[var(--border-subtle)] last:border-0 hover:bg-[var(--bg-hover)] transition-colors">
                  <td className="py-3 font-mono text-xs">#{p.id}</td>
                  <td className="py-3">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(p.status)}
                      {getStatusBadge(p.status)}
                    </div>
                    {p.failure_reason && (
                      <p className="text-xs text-red-400 mt-1 max-w-md">{p.failure_reason}</p>
                    )}
                  </td>
                  <td className="py-3 capitalize text-gray-300">{p.triggered_by}</td>
                  <td className="py-3">
                    {p.stages_completed ? (
                      <div className="flex gap-1 flex-wrap max-w-xs">
                        {p.stages_completed.split(", ").map(s => (
                          <span key={s} className={`text-xs px-1.5 py-0.5 rounded border ${
                            s === "Deploy" ? "bg-blue-500/10 border-blue-500/20 text-blue-300" : "bg-[#111827] border-[#1e2d4a]"
                          }`}>{s}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-gray-500">-</span>
                    )}
                  </td>
                  <td className="py-3 text-gray-400">{new Date(p.started_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
