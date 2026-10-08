import { useEffect, useState } from "react";
import { ShieldAlert, TriangleAlert, FileCode2, ScanSearch } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import api from "../lib/api";

const SEV_ORDER = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, UNKNOWN: 5 };

const SEV_COLORS = {
  CRITICAL: "border-red-600/40 bg-red-950/20",
  HIGH:     "border-orange-500/40 bg-orange-950/20",
  MEDIUM:   "border-yellow-500/40 bg-yellow-950/20",
  LOW:      "border-blue-500/40 bg-blue-950/20",
};

export default function IaCSecurity() {
  const [projects, setProjects]   = useState([]);
  const [selected, setSelected]   = useState("");
  const [data, setData]           = useState(null);
  const [loading, setLoading]     = useState(false);
  const [scanning, setScanning]   = useState(false);
  const [expanded, setExpanded]   = useState(null);
  const [severityTab, setSeverityTab] = useState("ALL");
  const [search, setSearch]       = useState("");

  // Load project list
  useEffect(() => {
    api.get("/projects")
      .then((r) => {
        const list = r.data.projects || [];
        setProjects(list);
        if (list.length) setSelected(String(list[0].id));
      })
      .catch(() => setProjects([]));
  }, []);

  // Load findings when project changes
  useEffect(() => {
    if (!selected) return;
    setLoading(true);
    setData(null);
    api.get(`/iac/${selected}`)
      .then((r) => setData(r.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [selected]);

  // Poll while scan is RUNNING
  useEffect(() => {
    const st = String(data?.latestScan?.status || "").toUpperCase();
    if (!selected || st !== "RUNNING") return undefined;
    const t = setInterval(() => {
      api.get(`/iac/${selected}`)
        .then((r) => setData(r.data))
        .catch(() => {});
    }, 4000);
    return () => clearInterval(t);
  }, [selected, data?.latestScan?.status]);

  const runScan = async () => {
    if (!selected) return;
    setScanning(true);
    try {
      await api.post(`/iac/scan/${selected}`, null, { timeout: 3_600_000 });
      const r = await api.get(`/iac/${selected}`);
      setData(r.data);
    } catch (error) {
      alert(error.response?.data?.error || "IaC scan failed");
      try {
        const r = await api.get(`/iac/${selected}`);
        setData(r.data);
      } catch { /* noop */ }
    } finally {
      setScanning(false);
    }
  };

  const summary   = data?.summary   || {};
  const allFindings = data?.findings || [];
  const latestScan  = data?.latestScan || null;
  const scanStatus  = String(latestScan?.status || "").toUpperCase();

  const filtered = allFindings.filter((f) => {
    const matchSev  = severityTab === "ALL" || (f.severity || "").toUpperCase() === severityTab;
    const matchSearch = search === "" ||
      `${f.config_file} ${f.misconfig_type} ${f.description}`.toLowerCase().includes(search.toLowerCase());
    return matchSev && matchSearch;
  });

  const filesScanned = new Set(allFindings.map((f) => f.config_file)).size;

  return (
    <div className="space-y-6">
      <PageHeader
        title="IaC Security Scanner"
        subtitle="Terraform · Docker · Kubernetes · CloudFormation — powered by Trivy"
        actions={
          <div className="flex items-center gap-3">
            <select
              className="input"
              value={selected}
              onChange={(e) => { setSelected(e.target.value); setExpanded(null); setSeverityTab("ALL"); }}
            >
              {projects.map((p) => (
                <option key={p.id} value={String(p.id)}>{p.name}</option>
              ))}
            </select>
            <button
              className="primary-btn inline-flex items-center gap-2"
              onClick={runScan}
              disabled={scanning || scanStatus === "RUNNING"}
            >
              <ScanSearch size={14} />
              {scanning || scanStatus === "RUNNING" ? "Scanning…" : "Run IaC Scan"}
            </button>
          </div>
        }
      />

      {/* Scan status banner */}
      {scanStatus === "RUNNING" && (
        <div className="card p-3 border border-blue-500/40 text-blue-300 text-sm flex items-center gap-2">
          <span className="animate-pulse">⏳</span> IaC scan is running… results will appear automatically.
        </div>
      )}
      {scanStatus === "FAILED" && (
        <div className="card p-3 border border-red-600/40 text-red-400 text-sm flex items-center gap-2">
          <TriangleAlert size={14} /> Last scan failed. Check backend logs for details.
        </div>
      )}

      {/* Summary cards */}
      <div className="grid md:grid-cols-5 gap-4">
        {[
          { label: "Files Scanned", value: filesScanned, icon: FileCode2, cls: "border-[#1e2d4a]" },
          { label: "Critical",  value: summary.critical ?? 0, icon: ShieldAlert, cls: SEV_COLORS.CRITICAL },
          { label: "High",      value: summary.high     ?? 0, icon: ShieldAlert, cls: SEV_COLORS.HIGH },
          { label: "Medium",    value: summary.medium   ?? 0, icon: ShieldAlert, cls: SEV_COLORS.MEDIUM },
          { label: "Low",       value: summary.low      ?? 0, icon: ShieldAlert, cls: SEV_COLORS.LOW },
        ].map(({ label, value, icon: Icon, cls }) => (
          <div key={label} className={`card p-4 border ${cls}`}>
            <div className="flex items-center gap-2 text-[#64748b] text-xs mb-1">
              <Icon size={12} /> {label}
            </div>
            <div className="text-2xl font-bold">{loading ? "—" : value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
          <button
            key={s}
            onClick={() => setSeverityTab(s)}
            className={`px-3 py-1.5 rounded-lg text-sm border ${severityTab === s ? "bg-blue-600 border-blue-500" : "border-[#1e2d4a]"}`}
          >
            {s}
          </button>
        ))}
        <input
          className="input w-full md:w-72 ml-auto"
          placeholder="Search findings…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Findings table */}
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-[#64748b] border-b border-[#1e2d4a]">
            <tr>
              <th className="p-3">Severity</th>
              <th>Config File</th>
              <th>Line</th>
              <th>Misconfiguration</th>
              <th>ID</th>
              <th>▼</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="p-6 text-center text-[#64748b]">Loading…</td></tr>
            )}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="p-6 text-center text-[#64748b]">
                  {allFindings.length === 0
                    ? (latestScan ? "No IaC misconfigurations found — clean scan! ✅" : "No scan run yet. Click Run IaC Scan to start.")
                    : "No findings match the current filter."}
                </td>
              </tr>
            )}
            {!loading && filtered.map((f, i) => (
              <>
                <tr key={f.id} className="border-b border-[#1e2d4a] hover:bg-[#0d1117]/40">
                  <td className="p-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="font-mono text-xs text-blue-400 max-w-[180px] truncate" title={f.config_file}>
                    {f.config_file?.split("/").slice(-2).join("/")}
                  </td>
                  <td className="text-[#94a3b8]">{f.start_line ?? "—"}</td>
                  <td className="max-w-[260px] truncate" title={f.misconfig_type}>{f.misconfig_type}</td>
                  <td className="font-mono text-xs text-[#64748b]">{f.misconfig_id || "—"}</td>
                  <td>
                    <button
                      onClick={() => setExpanded(expanded === i ? null : i)}
                      className="text-[#64748b] hover:text-white px-2"
                    >
                      {expanded === i ? "▲" : "▼"}
                    </button>
                  </td>
                </tr>
                {expanded === i && (
                  <tr key={`${f.id}-detail`} className="border-b border-[#1e2d4a]">
                    <td colSpan={6} className="p-4 bg-[#0a0e1a] space-y-3">
                      <div>
                        <p className="text-xs text-[#64748b] uppercase tracking-wide mb-1">Description</p>
                        <p className="text-sm text-[#e2e8f0]">{f.description || "No description available."}</p>
                      </div>
                      {f.resolution && (
                        <div className="bg-[#0d1a0d] border border-green-900/50 rounded p-3">
                          <p className="text-xs text-green-400 uppercase tracking-wide mb-1 flex items-center gap-1">
                            <ShieldAlert size={11} /> Remediation
                          </p>
                          <p className="text-sm text-green-200">{f.resolution}</p>
                        </div>
                      )}
                      <div className="grid md:grid-cols-3 gap-3 text-xs">
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-2">
                          <p className="text-[#64748b] mb-1">Config File</p>
                          <p className="font-mono text-[#e2e8f0] break-all">{f.config_file}</p>
                        </div>
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-2">
                          <p className="text-[#64748b] mb-1">Rule ID</p>
                          <p className="font-mono text-blue-400">{f.misconfig_id || "—"}</p>
                        </div>
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-2">
                          <p className="text-[#64748b] mb-1">Line</p>
                          <p className="font-mono text-[#e2e8f0]">{f.start_line ?? "—"}</p>
                        </div>
                      </div>
                      {f.misconfig_id && (
                        <a
                          href={`https://avd.aquasec.com/misconfig/${f.misconfig_id.toLowerCase()}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-blue-400 hover:text-blue-300 underline"
                        >
                          View Aqua AVD Rule Docs ↗
                        </a>
                      )}
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>

      {/* Last scan metadata */}
      {latestScan && (
        <p className="text-xs text-[#64748b] text-right">
          Last scan: {new Date(latestScan.completed_at || latestScan.started_at).toLocaleString()} ·
          Status: <span className={scanStatus === "COMPLETED" ? "text-green-400" : scanStatus === "FAILED" ? "text-red-400" : "text-yellow-400"}>{latestScan.status}</span>
        </p>
      )}
    </div>
  );
}
