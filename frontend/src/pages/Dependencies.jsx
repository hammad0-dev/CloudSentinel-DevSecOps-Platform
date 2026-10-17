import { executionResultsApi } from "../utils/executionScan";
import { useSearchParams } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import { Cell, PieChart, Pie, ResponsiveContainer, Tooltip } from "recharts";
import { AlertTriangle, Download, FileJson2, Package, ScanSearch, ShieldAlert } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import liveApi from "../lib/api";

const PIE_COLORS = ["#d06060", "#c89b3c", "#3e8f63", "#a9b4ad", "#8f79c6"];
const SEV_ORDER = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, NONE: 5, UNKNOWN: 6 };

export default function Dependencies() {
  const [searchParams] = useSearchParams();
  const executionId = searchParams.get("executionId");
  const reportProjectId = searchParams.get("projectId");
  const api = executionResultsApi(liveApi, reportProjectId, executionId);

  const [projects, setProjects] = useState([]);
  const [selected, setSelected] = useState("");
  const [tab, setTab] = useState("Vulnerabilities");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [sbomLoading, setSbomLoading] = useState(false);

  useEffect(() => {
    api
      .get("/projects")
      .then((r) => {
        const list = r.data.projects || [];
        setProjects(list);
        if (list.length) setSelected(reportProjectId || String(list[0].id));
      })
      .catch(() => setProjects([]));
  }, []);

  useEffect(() => {
    if (!selected) return;
    setLoading(true);
    api
      .get(`/dependencies/${selected}`)
      .then((r) => setData(r.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [selected, executionId]);

  useEffect(() => {
    const st = String(data?.latestScan?.status || "").toUpperCase();
    if (!selected || st !== "RUNNING") return undefined;
    const t = setInterval(() => {
      api
        .get(`/dependencies/${selected}`)
        .then((r) => setData(r.data))
        .catch(() => {});
    }, 4000);
    return () => clearInterval(t);
  }, [selected, data?.latestScan?.status]);

  const runScan = async () => {
    if (!selected) return;
    setScanning(true);
    try {
      await api.post(`/dependencies/scan/${selected}`, null, {
        timeout: 3_600_000,
      });
      const r = await api.get(`/dependencies/${selected}`);
      setData(r.data);
    } catch (error) {
      alert(error.response?.data?.error || "Scan failed");
      try {
        const r = await api.get(`/dependencies/${selected}`);
        setData(r.data);
      } catch {
        /* noop */
      }
    } finally {
      setScanning(false);
    }
  };

  const exportSbom = async () => {
    if (!selected) return;
    setSbomLoading(true);
    try {
      const r = await api.get(`/dependencies/sbom/${selected}`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([r.data], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `sbom-${selected}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      alert(error.response?.data?.error || "No SBOM available. Run a scan first.");
    } finally {
      setSbomLoading(false);
    }
  };

  const exportReport = async () => {
    if (!selected) return;
    try {
      const r = await api.get(`/dependencies/report/${selected}`);
      const project = r.data?.project || {};
      const summary = r.data?.summary || {};
      const rows = (r.data?.vulnerable || [])
        .map(
          (v) =>
            `<tr><td>${v.pkg_name || "-"}</td><td>${v.pkg_version || "-"}</td><td>${v.cve_id || "-"}</td><td>${v.severity || "-"}</td><td>${v.fixed_version || "-"}</td></tr>`
        )
        .join("");
      const html = `<!doctype html><html><head><meta charset="utf-8" /><title>Dependency Report</title><style>
        body{font-family:Inter,system-ui,sans-serif;background:#0f1412;color:#e7efe9;margin:24px}
        h1,h2{margin:0 0 8px}.muted{color:#a9b4ad}
        .card{background:#1a211e;border:1px solid #2f3934;border-radius:8px;padding:14px;margin:14px 0}
        .grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
        .kpi{background:#232b27;border:1px solid #3a4740;border-radius:8px;padding:10px}
        table{width:100%;border-collapse:collapse;font-size:13px}th,td{border:1px solid #2f3934;padding:8px;text-align:left}th{background:#232b27}
      </style></head><body>
        <h1>CloudSentinel Dependency Report</h1>
        <p class="muted">Generated at: ${new Date(r.data?.generatedAt || Date.now()).toLocaleString()}</p>
        <div class="card"><h2>Project</h2>
          <p><strong>Name:</strong> ${project.name || "-"}</p>
          <p><strong>Repository:</strong> ${project.repo_url || "-"}</p>
          <p><strong>Language:</strong> ${project.language || "Unknown"}</p>
        </div>
        <div class="card"><h2>Latest Scan Summary</h2><div class="grid">
          <div class="kpi"><div class="muted">Packages</div><div>${summary.total_packages ?? 0}</div></div>
          <div class="kpi"><div class="muted">Critical</div><div>${summary.critical ?? 0}</div></div>
          <div class="kpi"><div class="muted">High</div><div>${summary.high ?? 0}</div></div>
          <div class="kpi"><div class="muted">Medium</div><div>${summary.medium ?? 0}</div></div>
        </div></div>
        <div class="card"><h2>Vulnerabilities</h2>
          <table><thead><tr><th>Package</th><th>Installed</th><th>CVE</th><th>Severity</th><th>Fixed In</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5">No vulnerabilities found</td></tr>'}</tbody></table>
        </div>
      </body></html>`;
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `dependency-report-${selected}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert("Failed to export report");
    }
  };

  const vulnerable = useMemo(() => {
    if (!data?.vulnerable) return [];
    return [...data.vulnerable].sort(
      (a, b) => (SEV_ORDER[(a.severity || "UNKNOWN").toUpperCase()] || 9) - (SEV_ORDER[(b.severity || "UNKNOWN").toUpperCase()] || 9)
    );
  }, [data]);

  const licenseData = useMemo(() => {
    if (!data?.licenses) return [];
    return data.licenses.map((l, i) => ({ ...l, color: PIE_COLORS[i % PIE_COLORS.length] }));
  }, [data]);

  const scan = data?.latestScan;

  const stats = [
    { label: "Total Packages", value: scan?.total_packages ?? 0, icon: Package, color: "var(--text-primary)" },
    { label: "Critical", value: scan?.critical ?? 0, icon: ShieldAlert, color: "var(--accent-red)" },
    { label: "High", value: scan?.high ?? 0, icon: AlertTriangle, color: "var(--accent-yellow)" },
    { label: "Medium", value: (scan?.medium ?? 0), icon: AlertTriangle, color: "var(--accent-blue)" },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dependencies & SBOM"
        subtitle="Trivy-powered supply chain vulnerability scanning"
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            <select className="input" value={selected} disabled={Boolean(executionId)} onChange={(e) => setSelected(e.target.value)}>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            <button className="primary-btn inline-flex items-center gap-2" onClick={runScan} disabled={Boolean(executionId) || scanning || !selected}>
              <ScanSearch size={14} />
              {scanning ? "Scanning..." : "Run Scan"}
            </button>
            <button className="secondary-btn inline-flex items-center gap-2" onClick={exportSbom} disabled={Boolean(executionId) || sbomLoading || !selected}>
              <FileJson2 size={14} />
              {sbomLoading ? "Exporting..." : "Export SBOM"}
            </button>
            <button className="secondary-btn inline-flex items-center gap-2" onClick={exportReport} disabled={Boolean(executionId) || !selected}>
              <Download size={14} />
              Export Report
            </button>
          </div>
        }
      />

      {scan && (
        <div className="card px-4 py-2 text-xs text-[var(--text-secondary)] flex items-center gap-4 flex-wrap">
          <span>Last scan: {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—"}</span>
          <span className={`pill-badge ${scan.status === "COMPLETED" ? "border-[var(--accent-green)] text-[var(--accent-green)]" : scan.status === "FAILED" ? "border-[var(--accent-red)] text-[var(--accent-red)]" : "border-[var(--accent-yellow)] text-[var(--accent-yellow)]"}`}>
            {scan.status}
          </span>
        </div>
      )}

      <div className="grid md:grid-cols-4 gap-4">
        {stats.map((s) => (
          <div key={s.label} className="card p-4">
            <p className="text-xs text-[var(--text-secondary)] flex items-center gap-2">
              <s.icon size={14} style={{ color: s.color }} />
              {s.label}
            </p>
            <p className="text-3xl font-semibold mt-2" style={{ color: s.color }}>{s.value}</p>
          </div>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap">
        {["Vulnerabilities", "All Packages", "Licenses", "SBOM Tree"].map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 rounded-md text-sm border transition-all ${tab === t ? "border-[var(--accent-green)] text-[var(--accent-green)] bg-[rgba(62,143,99,0.12)]" : "border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"}`}
          >
            {t}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="card p-8 text-center text-[var(--text-secondary)]">Loading scan results...</div>
      ) : !data ? (
        <div className="card p-10 text-center">
          <Package className="mx-auto mb-3 text-[var(--accent-green)]" size={34} />
          <p className="font-semibold mb-1">No dependency scan yet</p>
          <p className="text-sm text-[var(--text-secondary)] mb-4">Run a scan to detect vulnerable dependencies and generate SBOM.</p>
          <button className="primary-btn" onClick={runScan} disabled={Boolean(executionId) || scanning || !selected}>
            {scanning ? "Scanning..." : "Run Scan Now"}
          </button>
        </div>
      ) : (
        <>
          {tab === "Vulnerabilities" && (
            <div className="card overflow-x-auto">
              <table className="gh-table">
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Installed</th>
                    <th>Fixed In</th>
                    <th>CVE</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerable.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="text-center text-[var(--text-secondary)] py-8">
                        No vulnerabilities found
                      </td>
                    </tr>
                  ) : (
                    vulnerable.map((r, i) => (
                      <tr key={`vuln-${i}`}>
                        <td className="font-mono text-xs">{r.pkg_name}</td>
                        <td>{r.pkg_version}</td>
                        <td className="text-[var(--accent-green)]">{r.fixed_version || "—"}</td>
                        <td className="font-mono text-xs">{r.cve_id || "—"}</td>
                        <td><SeverityBadge severity={r.severity} /></td>
                        <td>{r.cvss_score ?? "—"}</td>
                        <td className="text-xs text-[var(--text-secondary)] max-w-xs truncate">{r.description || "—"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {tab === "All Packages" && (
            <div className="card overflow-x-auto">
              <table className="gh-table">
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Type</th>
                    <th>License</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.packages || []).map((p, i) => (
                    <tr key={`pkg-${i}`}>
                      <td className="font-mono text-xs">{p.pkg_name}</td>
                      <td>{p.pkg_version}</td>
                      <td className="text-[var(--text-secondary)]">{p.pkg_type}</td>
                      <td className="text-[var(--text-secondary)]">{p.license || "Unknown"}</td>
                      <td>
                        {p.cve_id
                          ? <span className="pill-badge border-[var(--accent-red)] text-[var(--accent-red)]">Vulnerable</span>
                          : <span className="pill-badge border-[var(--accent-green)] text-[var(--accent-green)]">Safe</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {tab === "Licenses" && (
            <div className="card p-5 grid md:grid-cols-2 gap-6">
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={licenseData} dataKey="value" nameKey="name" innerRadius={60} outerRadius={90}>
                      {licenseData.map((l) => <Cell key={l.name} fill={l.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="space-y-2">
                {licenseData.map((l) => (
                  <div key={l.name} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <span className="w-3 h-3 rounded-full" style={{ background: l.color }} />
                      {l.name}
                    </div>
                    <span className="text-[var(--text-secondary)]">{l.value}</span>
                  </div>
                ))}
                {licenseData.some((l) => l.name.toUpperCase().includes("GPL")) && (
                  <div className="mt-4 p-3 rounded-md border border-[var(--accent-yellow)] bg-[rgba(200,155,60,0.10)] text-[var(--accent-yellow)] text-sm">
                    GPL-licensed packages may require source disclosure.
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === "SBOM Tree" && (
            <div className="card p-5">
              <p className="text-sm text-[var(--text-secondary)] mb-3">Software Bill of Materials — component tree</p>
              <div className="overflow-x-auto">
                <table className="gh-table text-xs">
                  <thead>
                    <tr>
                      <th>Component</th>
                      <th>Version</th>
                      <th>Ecosystem</th>
                      <th>License</th>
                      <th>CVEs</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...new Map((data.packages || []).map((p) => [`${p.pkg_name}@${p.pkg_version}`, p])).values()].map((p, i) => (
                      <tr key={`sbom-${i}`}>
                        <td className="font-mono">{p.pkg_name}</td>
                        <td>{p.pkg_version}</td>
                        <td className="text-[var(--text-secondary)]">{p.pkg_type}</td>
                        <td className="text-[var(--text-secondary)]">{p.license || "Unknown"}</td>
                        <td>
                          {(data.packages || []).filter((x) => x.pkg_name === p.pkg_name && x.cve_id).length || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
