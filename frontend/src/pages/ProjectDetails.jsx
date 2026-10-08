import { useEffect, useState } from "react";
import { ArrowLeft, ExternalLink, Github, ScanSearch } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import toast from "react-hot-toast";
import PageHeader from "../components/PageHeader";
import api from "../lib/api";
import { readLocalProjects, upsertLocalProject } from "../lib/projectStorage";

const normalize = (project, latestScanFromApi = null) => {
  const latestScan = latestScanFromApi ?? project.latestScan ?? null;
  const ls = String(latestScan?.status ?? "").toUpperCase();
  let status = project.status || "Pending";
  if (ls === "RUNNING") status = "Scanning";
  else if (ls === "FAILED") status = "Failed";
  else if (ls === "COMPLETED") status = "Active";
  const lastScanTime =
    project.lastScanTime ||
    project.last_scan_time ||
    latestScan?.completed_at ||
    project.created_at ||
    null;

  return {
    id: project.id || "",
    projectName: project.projectName || project.name || "Untitled project",
    repositoryUrl: project.repositoryUrl || project.repo_url || "",
    stack: project.stack || project.language || "Other",
    description: project.description || "No description provided.",
    status,
    lastScanTime,
  };
};

const statusStyles = {
  Active: "border-[var(--accent-green)] text-[var(--accent-green)]",
  Scanning: "border-[var(--accent-purple)] text-[var(--accent-purple)]",
  Failed: "border-[var(--accent-red)] text-[var(--accent-red)]",
  Pending: "border-[var(--accent-yellow)] text-[var(--accent-yellow)]",
  Archived: "border-[var(--text-tertiary)] text-[var(--text-tertiary)]",
};

export default function ProjectDetails() {
  const { id } = useParams();
  const [project, setProject] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const { data } = await api.get(`/projects/${id}`);
        setProject(normalize(data.project || {}, data.latestScan ?? null));
        try {
          const scansRes = await api.get(`/projects/${id}/scans`);
          setScanHistory(scansRes.data.scans || []);
        } catch {
          setScanHistory([]);
        }
      } catch {
        const local = readLocalProjects().find((p) => String(p.id) === String(id));
        setProject(local ? normalize(local, null) : null);
        setScanHistory([]);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  useEffect(() => {
    if (!id || project?.status !== "Scanning") return undefined;
    const t = setInterval(async () => {
      try {
        const { data } = await api.get(`/projects/${id}`);
        setProject(normalize(data.project || {}, data.latestScan ?? null));
        const scansRes = await api.get(`/projects/${id}/scans`);
        setScanHistory(scansRes.data.scans || []);
      } catch {
        /* ignore transient errors while polling */
      }
    }, 5000);
    return () => clearInterval(t);
  }, [id, project?.status]);

  const onScan = async () => {
    if (!project) return;
    setProject((prev) => ({ ...prev, status: "Scanning" }));
    try {
      await api.post(`/sast/scan/${id}`, null, { timeout: 3_600_000 });
      const detail = await api.get(`/projects/${id}`);
      const p = normalize(detail.data.project || {}, detail.data.latestScan ?? null);
      setProject(p);
      upsertLocalProject(p);
      const scansRes = await api.get(`/projects/${id}/scans`);
      setScanHistory(scansRes.data.scans || []);
      toast.success("SAST scan completed");
    } catch (error) {
      toast.error(error.response?.data?.error || "SAST scan failed");
      try {
        const detail = await api.get(`/projects/${id}`);
        setProject(normalize(detail.data.project || {}, detail.data.latestScan ?? null));
        const scansRes = await api.get(`/projects/${id}/scans`);
        setScanHistory(scansRes.data.scans || []);
      } catch {
        /* keep current UI */
      }
    }
  };

  if (loading) return <div className="card p-6">Loading project...</div>;
  if (!project) return <div className="card p-6">Project not found. <Link className="text-[var(--accent-green)]" to="/projects">Go back</Link>.</div>;

  return (
    <div className="space-y-6">
      <PageHeader
        title={project.projectName}
        subtitle="Project details"
        actions={
          <div className="flex gap-2">
            <Link className="secondary-btn" to="/projects">
              <ArrowLeft size={14} className="inline mr-1" />
              Back
            </Link>
            <Link className="secondary-btn" to={`/projects/${id}/sast`}>
              View SAST Results
            </Link>
            <Link className="secondary-btn" to={`/projects/${id}/iac`}>
              View IaC Results
            </Link>
            <Link className="secondary-btn" to={`/projects/${id}/dast`}>
              View DAST Results
            </Link>
            <button className="primary-btn" onClick={onScan}>
              <ScanSearch size={14} className="inline mr-1" />
              Scan
            </button>
          </div>
        }
      />

      <div className="card p-6 space-y-4">
        <p><span className="text-[var(--text-secondary)]">Repository:</span>{" "}
          <a href={project.repositoryUrl} target="_blank" rel="noreferrer" className="text-[var(--accent-green)] inline-flex items-center gap-1 hover:underline">
            <Github size={14} />{project.repositoryUrl}<ExternalLink size={12} />
          </a>
        </p>
        <p><span className="text-[var(--text-secondary)]">Stack:</span> {project.stack}</p>
        <p><span className="text-[var(--text-secondary)]">Description:</span> {project.description}</p>
        <p><span className="text-[var(--text-secondary)]">Last scan:</span> {project.lastScanTime ? new Date(project.lastScanTime).toLocaleString() : "Not scanned yet"}</p>
        <div className="flex gap-2">
          <span className={`pill-badge ${statusStyles[project.status] || statusStyles.Pending}`}>{project.status}</span>
        </div>
      </div>

      <div className="card p-6">
        <h3 className="text-lg font-semibold mb-4">Scan History</h3>
        {scanHistory.length === 0 ? (
          <p className="text-[var(--text-secondary)]">No scans yet. Run a scan once to populate this history.</p>
        ) : (
          <div className="space-y-3">
            {scanHistory.map((scan) => (
              <div key={scan.id} className="rounded-md border border-[var(--border-subtle)] bg-[var(--bg-tertiary)] p-3">
                <div className="flex flex-wrap justify-between gap-2 text-sm">
                  <span className="font-medium">{scan.scan_type || "Scan"}</span>
                  <span className="text-[var(--text-secondary)]">{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "In progress"}</span>
                </div>
                <div className="text-xs text-[var(--text-secondary)] mt-1">
                  Status: {scan.status}{" "}
                  {typeof scan.total_issues === "number"
                    ? `| Issues: ${scan.total_issues} (C:${scan.critical || 0} H:${scan.high || 0} M:${scan.medium || 0} L:${scan.low || 0})`
                    : ""}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
