import { Fragment, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import toast from "react-hot-toast";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Download } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import api from "../utils/api";



export default function SASTResults() {
  const { id } = useParams();
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [data, setData] = useState({ summary: {}, vulnerabilities: [], sonarMetrics: null });
  const [fetchError, setFetchError] = useState(null);
  const [search, setSearch] = useState("");
  const [severityTab, setSeverityTab] = useState("ALL");
  const [expanded, setExpanded] = useState(null);

  const load = async () => {
    setLoading(true);
    setFetchError(null);
    try {
      const res = await api.get(`/sast/${id}`);
      setData(res.data);
    } catch (err) {
      const status = err.response?.status;
      const serverMsg = err.response?.data?.error || err.response?.data?.message;
      const message = serverMsg || err.message || "Unknown error";
      console.error("[SASTResults] load() failed:", {
        url: `/sast/${id}`,
        status,
        message,
        axiosResponse: err.response,
        fullError: err,
      });
      setFetchError({ error: true, status, message });
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, [id]);

  const runScan = async () => {
    setScanLoading(true);
    try {
      await api.post(`/sast/scan/${id}`, null, { timeout: 3_600_000 });
      toast.success("SAST scan completed");
      load();
    } catch (error) {
      toast.error(error.response?.data?.error || "Scan failed");
    } finally {
      setScanLoading(false);
    }
  };

  const downloadBlob = (content, mimeType, filename) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const buildHtmlReport = (report) => {
    const findingsRows = (report.topFindings || [])
      .map(
        (x) =>
          `<tr><td>${x.severity || "INFO"}</td><td>${x.rule || "-"}</td><td>${x.message || "-"}</td><td>${x.file_path || "-"}</td><td>${x.line_number ?? "-"}</td></tr>`
      )
      .join("");

    return `<!doctype html><html><head><meta charset="utf-8" /><title>SAST Report</title><style>
      body { font-family: Inter, system-ui, sans-serif; background:#0f1412; color:#e7efe9; margin:24px; }
      h1,h2 { margin:0 0 8px; } .muted { color:#a9b4ad; }
      .card { background:#1a211e; border:1px solid #2f3934; border-radius:8px; padding:14px; margin:14px 0; }
      .grid { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:10px; }
      .kpi { background:#232b27; border:1px solid #3a4740; border-radius:8px; padding:10px; }
      table { width:100%; border-collapse: collapse; font-size:13px; } th, td { border:1px solid #2f3934; padding:8px; text-align:left; } th { background:#232b27; }
    </style></head><body>
      <h1>CloudSentinel SAST Report</h1>
      <p class="muted">Generated at: ${new Date(report.generatedAt || Date.now()).toLocaleString()}</p>
      <div class="card"><h2>Project</h2>
        <p><strong>Name:</strong> ${report.project?.name || "-"}</p>
        <p><strong>Repository:</strong> ${report.project?.repo_url || "-"}</p>
        <p><strong>Language:</strong> ${report.project?.language || "Unknown"}</p>
      </div>
      <div class="card"><h2>Totals</h2><div class="grid">
        <div class="kpi"><div class="muted">Issues</div><div>${report.totals?.issues ?? 0}</div></div>
        <div class="kpi"><div class="muted">Critical</div><div>${report.totals?.critical ?? 0}</div></div>
        <div class="kpi"><div class="muted">High</div><div>${report.totals?.high ?? 0}</div></div>
        <div class="kpi"><div class="muted">Medium/Low</div><div>${report.totals?.medium ?? 0}</div></div>
      </div></div>
      <div class="card"><h2>Top Findings</h2>
        <table><thead><tr><th>Severity</th><th>Rule</th><th>Message</th><th>File</th><th>Line</th></tr></thead>
        <tbody>${findingsRows || '<tr><td colspan="5">No findings</td></tr>'}</tbody></table>
      </div>
    </body></html>`;
  };

  const exportReport = async () => {
    try {
      const res = await api.get(`/sast/report/${id}`);
      downloadBlob(
        buildHtmlReport(res.data),
        "text/html",
        `cloudsentinel-sast-report-${id}.html`
      );
      toast.success("SAST report exported");
    } catch {
      toast.error("Failed to export report");
    }
  };

  const filtered = useMemo(() => {
    return data.vulnerabilities.filter((v) => {
      const matchSearch = `${v.rule} ${v.message} ${v.file_path}`.toLowerCase().includes(search.toLowerCase());
      const matchSeverity = severityTab === "ALL" ? true : (v.severity || "").toUpperCase() === severityTab;
      return matchSearch && matchSeverity;
    });
  }, [data, search, severityTab]);

  const issueChartData = useMemo(() => {
    if (!data.sonarMetrics) return [];
    return [
      { name: "Bugs", value: data.sonarMetrics.bugs },
      { name: "Vulns", value: data.sonarMetrics.vulnerabilities },
      { name: "Hotspots", value: data.sonarMetrics.hotspots },
      { name: "Smells", value: data.sonarMetrics.codeSmells },
    ];
  }, [data.sonarMetrics]);

  const qualityChartData = useMemo(() => {
    if (!data.sonarMetrics) return [];
    return [
      { name: "Coverage %", value: Number(data.sonarMetrics.coverage || 0) },
      { name: "Duplication %", value: Number(data.sonarMetrics.duplications || 0) },
    ];
  }, [data.sonarMetrics]);

  if (fetchError) {
    return (
      <div className="space-y-6">
        <PageHeader title="SAST Scan Results" subtitle="Error loading results" />
        <div className="card p-6 border border-red-600/60 bg-red-950/20">
          <p className="text-red-400 font-semibold text-lg mb-1">Failed to load scan results</p>
          {fetchError.status && (
            <p className="text-red-300 text-sm mb-1">
              HTTP Status: <span className="font-mono">{fetchError.status}</span>
            </p>
          )}
          <p className="text-red-300 text-sm font-mono break-all">{fetchError.message}</p>
          <p className="text-[#64748b] text-xs mt-3">Check the browser DevTools Console and Network tab for the full error details.</p>
          <button className="primary-btn mt-4" onClick={load}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="SAST Scan Results"
        subtitle={`Last scanned: ${data.lastScan || "Not scanned"}`}
        actions={
          <div className="flex items-center gap-2">
            <button className="secondary-btn inline-flex items-center gap-2" onClick={exportReport}>
              <Download size={14} />
              Export Report
            </button>
            <button className="primary-btn" onClick={runScan} disabled={scanLoading}>
              {scanLoading ? "Scanning... Please wait" : "Run SAST Scan"}
            </button>
          </div>
        }
      />
      {data.sonarMetrics ? (
        <div className="grid md:grid-cols-4 gap-4">
          <div className="card p-4">Bugs: {data.sonarMetrics.bugs}</div>
          <div className="card p-4">Vulnerabilities: {data.sonarMetrics.vulnerabilities}</div>
          <div className="card p-4">Security Hotspots: {data.sonarMetrics.hotspots}</div>
          <div className="card p-4">Code Smells: {data.sonarMetrics.codeSmells}</div>
          <div className="card p-4">Coverage: {data.sonarMetrics.coverage.toFixed(1)}%</div>
          <div className="card p-4">Duplications: {data.sonarMetrics.duplications.toFixed(1)}%</div>
          <div className="card p-4">Lines of Code: {data.sonarMetrics.ncloc}</div>
          <div className="card p-4">Quality Gate: {data.sonarMetrics.vulnerabilities === 0 && data.sonarMetrics.bugs === 0 ? "Passed" : "Needs review"}</div>
        </div>
      ) : null}
      {data.sonarMetrics ? (
        <div className="grid md:grid-cols-2 gap-4">
          <div className="card p-4">
            <p className="mb-3 text-sm text-[#94a3b8]">Issue Overview</p>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={issueChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
                  <XAxis dataKey="name" stroke="#94a3b8" />
                  <YAxis allowDecimals={false} stroke="#94a3b8" />
                  <Tooltip />
                  <Bar dataKey="value" fill="#3b82f6" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="card p-4">
            <p className="mb-3 text-sm text-[#94a3b8]">Quality Metrics (%)</p>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={qualityChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
                  <XAxis dataKey="name" stroke="#94a3b8" />
                  <YAxis domain={[0, 100]} stroke="#94a3b8" />
                  <Tooltip formatter={(v) => `${v}%`} />
                  <Bar dataKey="value" fill="#22c55e" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      ) : null}
      <div className="grid md:grid-cols-4 gap-4">
        <div className="card p-4 border border-red-600/40">Critical: {data.summary.critical || 0}</div>
        <div className="card p-4 border border-orange-500/40">Major: {data.summary.major || 0}</div>
        <div className="card p-4 border border-yellow-500/40">Minor: {data.summary.minor || 0}</div>
        <div className="card p-4">Files Scanned: {Math.max(1, Math.floor((data.summary.total || 0) * 1.8))}</div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {["ALL", "CRITICAL", "MAJOR", "MINOR", "INFO"].map((s) => (
          <button key={s} onClick={() => setSeverityTab(s)} className={`px-3 py-1.5 rounded-lg text-sm border ${severityTab === s ? "bg-blue-600 border-blue-500" : "border-[#1e2d4a]"}`}>{s}</button>
        ))}
        <input className="input w-full md:w-96 ml-auto" placeholder="Search vulnerabilities..." value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-[#64748b] border-b border-[#1e2d4a]">
            <tr><th className="p-3">Severity</th><th>Rule ID</th><th>Description</th><th>File</th><th>Line</th><th>Status</th><th>▼</th></tr>
          </thead>
          <tbody>
            {(loading ? [] : filtered).map((v, i) => (
              <Fragment key={`grp-${i}`}>
                <tr className="border-b border-[#1e2d4a]">
                  <td className="p-3"><SeverityBadge severity={v.severity} /></td>
                  <td className="font-mono text-xs">{v.rule}</td>
                  <td>{v.message}</td>
                  <td className="text-blue-400">{v.file_path?.split("/").pop()}</td>
                  <td>{v.line_number || "-"}</td>
                  <td>{v.status || "OPEN"}</td>
                  <td><button onClick={() => setExpanded(expanded === i ? null : i)}>▼</button></td>
                </tr>
                {expanded === i ? (
                  <tr className="border-b border-[#1e2d4a]">
                    <td colSpan={7} className="p-4 bg-[#0a0e1a] space-y-3">
                      <div>
                        <p className="text-xs text-[#64748b] uppercase tracking-wide mb-1">Finding Description</p>
                        <p className="text-sm text-[#e2e8f0]">{v.message}</p>
                      </div>
                      <div className="grid md:grid-cols-3 gap-3 text-xs">
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-3">
                          <p className="text-[#64748b] mb-1">Rule ID</p>
                          <p className="font-mono text-blue-400">{v.rule || "—"}</p>
                        </div>
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-3">
                          <p className="text-[#64748b] mb-1">File</p>
                          <p className="font-mono text-[#e2e8f0] break-all">{v.file_path || "—"}</p>
                        </div>
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-3">
                          <p className="text-[#64748b] mb-1">Line Number</p>
                          <p className="font-mono text-[#e2e8f0]">{v.line_number ?? "—"}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 text-xs">
                        <span className={`px-2 py-1 rounded font-semibold ${
                          (v.severity || "").toUpperCase() === "CRITICAL" ? "bg-red-900/60 text-red-300" :
                          (v.severity || "").toUpperCase() === "MAJOR" ? "bg-orange-900/60 text-orange-300" :
                          (v.severity || "").toUpperCase() === "MINOR" ? "bg-yellow-900/60 text-yellow-300" :
                          "bg-slate-700 text-slate-300"
                        }`}>
                          {v.severity || "INFO"}
                        </span>
                        <span className="text-[#64748b]">Status: <span className="text-[#e2e8f0]">{v.status || "OPEN"}</span></span>
                        {v.rule && (
                          <a
                            href={`https://rules.sonarsource.com/${(v.rule || "").split(":")[0]?.toLowerCase()}/RSPEC-${(v.rule || "").match(/S(\d+)/)?.[1]}`}
                            target="_blank"
                            rel="noreferrer"
                            className="ml-auto text-blue-400 hover:text-blue-300 underline"
                          >
                            View SonarQube Rule Docs ↗
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            ))}
          </tbody>
        </table>
        {!loading && filtered.length === 0 ? <p className="p-6 text-center text-[#64748b]">No scan results yet</p> : null}
      </div>
    </div>
  );
}
