import { useEffect, useState } from "react";
import { ExternalLink, FolderOpen, Github, Loader2, Plus, ScanSearch, Trash2 } from "lucide-react";
import toast from "react-hot-toast";
import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";
import api from "../lib/api";
import { readLocalProjects, upsertLocalProject, writeLocalProjects } from "../lib/projectStorage";
import { deleteErrorMessage } from "../utils/projectErrors";

const emptyForm = { projectName: "", repositoryUrl: "", githubToken: "", description: "" };
const statusStyles = {
  Active: "border-[var(--accent-green)] text-[var(--accent-green)]",
  Scanning: "border-[var(--accent-purple)] text-[var(--accent-purple)]",
  Failed: "border-[var(--accent-red)] text-[var(--accent-red)]",
  Pending: "border-[var(--accent-yellow)] text-[var(--accent-yellow)]",
  Archived: "border-[var(--text-tertiary)] text-[var(--text-tertiary)]",
};

const normalize = (project) => {
  const latestScan = project.latestScan;
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
    id: project.id || Date.now(),
    projectName: project.projectName || project.name || "Untitled project",
    repositoryUrl: project.repositoryUrl || project.repo_url || "",
    stack: project.stack || project.language || "Auto-detected after analysis",
    status,
    lastScanTime,
  };
};

export default function ProjectsPage() {
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [saving, setSaving] = useState(false);
  const [errors, setErrors] = useState({});
  const [form, setForm] = useState(emptyForm);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const { data } = await api.get("/projects");
        const list = (data.projects || []).map(normalize);
        setProjects(list);
        writeLocalProjects(list);
      } catch {
        setProjects(readLocalProjects().map(normalize));
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const validate = () => {
    const next = {};
    if (!form.projectName.trim()) next.projectName = "Project name is required";
    if (!form.repositoryUrl.trim()) next.repositoryUrl = "Repository URL is required";
    else if (!/^https:\/\/github\.com\/.+/i.test(form.repositoryUrl.trim())) next.repositoryUrl = "URL must start with https://github.com/";
    setErrors(next);
    return Object.keys(next).length === 0;
  };

  const registerProject = async (e) => {
    e.preventDefault();
    if (!validate()) return;
    setSaving(true);
    const payload = {
      projectName: form.projectName.trim(),
      repositoryUrl: form.repositoryUrl.trim(),
      githubToken: form.githubToken.trim() || undefined,
      description: form.description.trim(),
    };
    try {
      const { data } = await api.post("/projects", payload);
      const created = normalize({ ...payload, ...(data.project || {}), status: "Active" });
      setProjects((prev) => [created, ...prev]);
      upsertLocalProject(created);
      toast.success("Project registered");
    } catch (error) {
      const fallback = normalize({ id: `local-${Date.now()}`, ...payload, status: "Pending" });
      setProjects((prev) => [fallback, ...prev]);
      upsertLocalProject(fallback);
      toast.error(error.response?.data?.error || "API unavailable. Saved locally for now.");
    } finally {
      setSaving(false);
      setShowModal(false);
      setErrors({});
      setForm(emptyForm);
    }
  };

  const deleteProject = async (id) => {
    if (!window.confirm("Delete this project?")) return;
    const sid = String(id);
    const dropFromState = (prev) => {
      const next = prev.filter((p) => String(p.id) !== sid);
      writeLocalProjects(next);
      return next;
    };
    if (sid.startsWith("local-")) {
      setProjects((prev) => dropFromState(prev));
      toast.success("Project removed");
      return;
    }
    try {
      await api.delete(`/projects/${id}`);
      toast.success("Project deleted");
      setProjects((prev) => dropFromState(prev));
    } catch (error) {
      toast.error(deleteErrorMessage(error));
      if (error.response?.status === 404) {
        setProjects((prev) => dropFromState(prev));
      }
    }
  };

  const scanProject = async (project) => {
    setProjects((prev) => prev.map((p) => (p.id === project.id ? { ...p, status: "Scanning" } : p)));
    try {
      await api.post(`/sast/scan/${project.id}`, null, { timeout: 3_600_000 });
      const { data } = await api.get("/projects");
      const list = (data.projects || []).map(normalize);
      setProjects(list);
      writeLocalProjects(list);
      toast.success("SAST scan completed");
    } catch (error) {
      toast.error(error.response?.data?.error || "SAST scan failed");
      try {
        const { data } = await api.get("/projects");
        setProjects((data.projects || []).map(normalize));
      } catch {
        /* noop */
      }
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader title="My Projects" subtitle={`${projects.length} registered`} actions={<button className="primary-btn" onClick={() => setShowModal(true)}><Plus size={16} className="inline mr-1" />Add Project</button>} />

      {loading ? <div className="card p-6 text-[var(--text-secondary)]">Loading projects...</div> : projects.length === 0 ? (
        <div className="card p-10 text-center">
          <FolderOpen className="mx-auto text-[var(--accent-green)] mb-3" size={34} />
          <h3 className="text-lg font-semibold mb-2">No projects yet</h3>
          <p className="text-[var(--text-secondary)] mb-5">No projects yet. Connect your first repository.</p>
          <button className="primary-btn" onClick={() => setShowModal(true)}><Plus size={16} className="inline mr-1" />Add Project</button>
        </div>
      ) : (
        <div className="grid gap-4">
          {projects.map((raw) => {
            const project = normalize(raw);
            return (
              <div key={project.id} className="card p-5">
                <div className="grid md:grid-cols-6 gap-4 items-center">
                  <div className="md:col-span-2"><p className="font-semibold">{project.projectName}</p><a href={project.repositoryUrl} target="_blank" rel="noreferrer" className="text-sm text-[var(--accent-green)] inline-flex items-center gap-1 hover:underline break-all"><Github size={14} />{project.repositoryUrl}<ExternalLink size={12} /></a></div>
                  <div className="text-sm text-[var(--text-secondary)]">{project.stack}</div>
                  <div><span className={`pill-badge ${statusStyles[project.status] || statusStyles.Pending}`}>{project.status}</span></div>
                  <div className="text-sm text-[var(--text-secondary)]">{project.lastScanTime ? new Date(project.lastScanTime).toLocaleString() : "Not scanned yet"}</div>
                  <div className="flex flex-wrap gap-2">
                    <button className="primary-btn text-sm" onClick={() => scanProject(project)}><ScanSearch size={14} className="inline mr-1" />Scan</button>
                    <Link className="secondary-btn text-sm" to={`/projects/${project.id}`}>View</Link>
                    <button className="danger-btn text-sm" onClick={() => deleteProject(project.id)}><Trash2 size={14} className="inline mr-1" />Delete</button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {showModal ? (
        <div className="fixed inset-0 z-50 bg-black/70 overflow-y-auto">
          <div className="min-h-full w-full flex items-start justify-center p-4 pt-16">
            <form onSubmit={registerProject} className="w-full max-w-xl rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-6 space-y-4">
            <h3 className="text-xl font-semibold">Register Project</h3>
            <div><label className="text-sm text-[var(--text-secondary)]">Project Name</label><input className={`input w-full mt-1 ${errors.projectName ? "border-[var(--accent-red)]" : ""}`} value={form.projectName} onChange={(e) => setForm((prev) => ({ ...prev, projectName: e.target.value }))} />{errors.projectName ? <p className="text-xs text-[var(--accent-red)] mt-1">{errors.projectName}</p> : null}</div>
            <div><label className="text-sm text-[var(--text-secondary)]">GitHub Repository URL</label><input className={`input w-full mt-1 ${errors.repositoryUrl ? "border-[var(--accent-red)]" : ""}`} placeholder="https://github.com/owner/repository" value={form.repositoryUrl} onChange={(e) => setForm((prev) => ({ ...prev, repositoryUrl: e.target.value }))} />{errors.repositoryUrl ? <p className="text-xs text-[var(--accent-red)] mt-1">{errors.repositoryUrl}</p> : null}</div>
            <div>
              <label className="text-sm text-[var(--text-secondary)]">GitHub Personal Access Token (optional)</label>
              <input
                type="password"
                className="input w-full mt-1"
                placeholder="Only needed for private repositories"
                value={form.githubToken}
                onChange={(e) => setForm((prev) => ({ ...prev, githubToken: e.target.value }))}
              />
              <p className="text-xs text-[var(--text-secondary)] mt-1">
                Public repositories usually do not need a token. For private repositories, provide a PAT with repo access.
              </p>
            </div>
            <div><label className="text-sm text-[var(--text-secondary)]">Description (optional)</label><textarea className="input w-full mt-1 min-h-24" value={form.description} onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))} /></div>
              <div className="flex justify-end gap-2"><button type="button" className="secondary-btn" onClick={() => setShowModal(false)}>Cancel</button><button type="submit" className="primary-btn min-w-40" disabled={saving}>{saving ? <><Loader2 size={14} className="inline mr-1 animate-spin" />Registering...</> : "Register Project"}</button></div>
            </form>
          </div>
        </div>
      ) : null}
    </div>
  );
}
