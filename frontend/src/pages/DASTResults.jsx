import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { ShieldAlert, ScanSearch, TriangleAlert, Link2, Save } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import api from "../lib/api";

const SEV_COLORS = {
  HIGH:          "border-red-600/40 bg-red-950/20",
  MEDIUM:        "border-orange-500/40 bg-orange-950/20",
  LOW:           "border-yellow-500/40 bg-yellow-950/20",
  INFORMATIONAL: "border-blue-500/40 bg-blue-950/20",
};

export default function DASTResults() {
  const { id } = useParams();                        // project id from URL
  const [data, setData]           = useState(null);
  const [loading, setLoading]     = useState(true);
  const [scanning, setScanning]   = useState(false);
  const [expanded, setExpanded]   = useState(null);
  const [severityTab, setSeverityTab] = useState("ALL");
  const [search, setSearch]       = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [savingUrl, setSavingUrl] = useState(false);
  const [fetchError, setFetchError] = useState(null);

  const load = async () => {
    if (!id) return;
    setLoading(true);
    setFetchError(null);
    try {
      const r = await api.get("/dast/" + id);
      setData(r.data);
      if (r.data.target_url) setTargetUrl(r.data.target_url);
    } catch (err) {
      const msg = err.response?.data?.error || err.message || "Unknown error";
      console.error("[DASTResults] load failed:", err);
      setFetchError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [id]);

  // Poll while scan is RUNNING
  useEffect(() => {
    const st = String(data?.latestScan?.status || "").toUpperCase();
    if (!id || st !== "RUNNING") return undefined;
    const t = setInterval(() => {
      api.get("/dast/" + id).then((r) => { setData(r.data); }).catch(() => {});
    }, 5000);
    return () => clearInterval(t);
  }, [id, data?.latestScan?.status]);

  const saveTargetUrl = async () => {
    if (!id || !targetUrl.trim()) return;
    setSavingUrl(true);
    try {
      await api.patch("/dast/target/" + id, { target_url: targetUrl.trim() });
      await load();
    } catch (err) {
      alert(err.response?.data?.error || "Failed to save target URL");
    } finally {
      setSavingUrl(false);
    }
  };

  const runScan = async () => {
    if (!id) return;
    setScanning(true);
    try {
      await api.post("/dast/scan/" + id, null, { timeout: 1_800_000 });
      await load();
    } catch (err) {
      alert(err.response?.data?.error || "DAST scan failed");
      await load();
    } finally {
      setScanning(false);
    }
  };

  const summary     = data?.summary   || {};
  const allFindings = data?.findings  || [];
  const latestScan  = data?.latestScan || null;
  const scanStatus  = String(latestScan?.status || "").toUpperCase();

  const filtered = allFindings.filter((f) => {
    const matchSev    = severityTab === "ALL" || (f.severity || "").toUpperCase() === severityTab;
    const matchSearch = search === "" ||
      [f.alert, f.endpoint, f.param, f.attack_type].join(" ").toLowerCase().includes(search.toLowerCase());
    return matchSev && matchSearch;
  });

  if (fetchError) {
    return (
      <div className="space-y-6">
        <PageHeader title="DAST Scan Results" subtitle="Dynamic Application Security Testing — OWASP ZAP" />
        <div className="card p-6 border border-red-600/40 text-red-400">
          <p className="font-semibold mb-1">Failed to load DAST results</p>
          <p className="text-sm">{fetchError}</p>
          <button className="mt-3 secondary-btn text-xs" onClick={load}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="DAST Scan Results"
        subtitle="Dynamic Application Security Testing — OWASP ZAP Baseline"
        actions={
          <button
            className="primary-btn inline-flex items-center gap-2"
            onClick={runScan}
            disabled={scanning || scanStatus === "RUNNING" || !data?.target_url}
            title={!data?.target_url ? "Set a target URL below first" : ""}
          >
            <ScanSearch size={14} />
            {scanning || scanStatus === "RUNNING" ? "Scanning…" : "Run DAST Scan"}
          </button>
        }
      />

      {/* Target URL configuration */}
      <div className="card p-4">
        <p className="text-xs text-[#64748b] uppercase tracking-wide mb-2 flex items-center gap-1">
          <Link2 size={11} /> DAST Target URL
        </p>
        <div className="flex items-center gap-2">
          <input
            className="input flex-1"
            placeholder="e.g. http://localhost:3001  (the running app ZAP will attack)"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
          <button
            className="secondary-btn inline-flex items-center gap-1"
            onClick={saveTargetUrl}
            disabled={savingUrl || !targetUrl.trim()}
          >
            <Save size={13} />
            {savingUrl ? "Saving…" : "Save"}
          </button>
        </div>
        {!data?.target_url && (
          <p className="text-xs text-yellow-400 mt-1">⚠ No target URL saved yet — save a URL above before scanning.</p>
        )}
        {data?.target_url && (
          <p className="text-xs text-green-400 mt-1">✓ Target: <span className="font-mono">{data.target_url}</span></p>
        )}
      </div>

      {/* Scan status banners */}
      {scanStatus === "RUNNING" && (
        <div className="card p-3 border border-blue-500/40 text-blue-300 text-sm flex items-center gap-2">
          <span className="animate-pulse">⏳</span> ZAP baseline scan is running against <span className="font-mono ml-1">{latestScan?.target_url}</span> — results will appear automatically (~2–5 min).
        </div>
      )}
      {scanStatus === "FAILED" && (
        <div className="card p-3 border border-red-600/40 text-red-400 text-sm flex items-center gap-2">
          <TriangleAlert size={14} /> Last scan failed. Make sure the target URL is reachable and the ZAP Docker image is pulled.
        </div>
      )}

      {/* Summary cards */}
      <div className="grid md:grid-cols-5 gap-4">
        {[
          { label: "Total Findings", value: summary.total         ?? 0, cls: "border-[#1e2d4a]" },
          { label: "High",           value: summary.high          ?? 0, cls: SEV_COLORS.HIGH },
          { label: "Medium",         value: summary.medium        ?? 0, cls: SEV_COLORS.MEDIUM },
          { label: "Low",            value: summary.low           ?? 0, cls: SEV_COLORS.LOW },
          { label: "Informational",  value: summary.informational ?? 0, cls: SEV_COLORS.INFORMATIONAL },
        ].map(({ label, value, cls }) => (
          <div key={label} className={`card p-4 border ${cls}`}>
            <div className="flex items-center gap-2 text-[#64748b] text-xs mb-1">
              <ShieldAlert size={12} /> {label}
            </div>
            <div className="text-2xl font-bold">{loading ? "—" : value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        {["ALL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((s) => (
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
          placeholder="Search findings, URLs, params…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Findings table */}
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-[#64748b] border-b border-[#1e2d4a]">
            <tr>
              <th className="p-3">Risk</th>
              <th>Alert</th>
              <th>Endpoint (URL)</th>
              <th>Method</th>
              <th>Param</th>
              <th>CWE</th>
              <th>▼</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={7} className="p-6 text-center text-[#64748b]">Loading…</td></tr>
            )}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="p-6 text-center text-[#64748b]">
                  {allFindings.length === 0
                    ? (latestScan ? "No DAST findings — clean scan! ✅" : "No scan run yet. Save a target URL above then click Run DAST Scan.")
                    : "No findings match the current filter."}
                </td>
              </tr>
            )}
            {!loading && filtered.map((f, i) => (
              <>
                <tr key={f.id} className="border-b border-[#1e2d4a] hover:bg-[#0d1117]/40">
                  <td className="p-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="max-w-[200px] truncate font-medium" title={f.alert}>{f.alert}</td>
                  <td className="font-mono text-xs text-blue-400 max-w-[220px] truncate" title={f.endpoint}>
                    {f.endpoint || "—"}
                  </td>
                  <td className="text-[#94a3b8]">{f.method || "—"}</td>
                  <td className="font-mono text-xs text-[#94a3b8] max-w-[100px] truncate" title={f.param}>{f.param || "—"}</td>
                  <td className="text-xs text-[#64748b]">{f.cwe_id ? "CWE-" + f.cwe_id : "—"}</td>
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
                  <tr key={f.id + "-detail"} className="border-b border-[#1e2d4a]">
                    <td colSpan={7} className="p-4 bg-[#0a0e1a] space-y-3">
                      {/* Attack payload */}
                      {f.request_payload && (
                        <div>
                          <p className="text-xs text-orange-400 uppercase tracking-wide mb-1">Attack Payload</p>
                          <pre className="bg-[#111827] border border-orange-900/40 rounded p-2 text-xs font-mono overflow-auto whitespace-pre-wrap break-all text-orange-200">{f.request_payload}</pre>
                        </div>
                      )}
                      {/* Response evidence */}
                      {f.response_details && (
                        <div>
                          <p className="text-xs text-[#64748b] uppercase tracking-wide mb-1">Response Evidence</p>
                          <pre className="bg-[#111827] border border-[#1e2d4a] rounded p-2 text-xs font-mono overflow-auto whitespace-pre-wrap break-all text-[#e2e8f0]">{f.response_details}</pre>
                        </div>
                      )}
                      {/* Remediation */}
                      {f.solution && (
                        <div className="bg-[#0d1a0d] border border-green-900/50 rounded p-3">
                          <p className="text-xs text-green-400 uppercase tracking-wide mb-1 flex items-center gap-1">
                            <ShieldAlert size={11} /> Remediation / Solution
                          </p>
                          <p className="text-sm text-green-200">{f.solution}</p>
                        </div>
                      )}
                      {/* Metadata row */}
                      <div className="grid md:grid-cols-4 gap-3 text-xs">
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-2">
                          <p className="text-[#64748b] mb-1">Full Endpoint</p>
                          <p className="font-mono text-[#e2e8f0] break-all">{f.endpoint || "—"}</p>
                        </div>
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-2">
                          <p className="text-[#64748b] mb-1">HTTP Method</p>
                          <p className="font-mono text-[#e2e8f0]">{f.method || "—"}</p>
                        </div>
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-2">
                          <p className="text-[#64748b] mb-1">Parameter</p>
                          <p className="font-mono text-[#e2e8f0] break-all">{f.param || "—"}</p>
                        </div>
                        <div className="bg-[#111827] border border-[#1e2d4a] rounded p-2">
                          <p className="text-[#64748b] mb-1">CWE</p>
                          {f.cwe_id ? (
                            <a href={"https://cwe.mitre.org/data/definitions/" + f.cwe_id + ".html"} target="_blank" rel="noreferrer" className="font-mono text-blue-400 hover:text-blue-300 underline">
                              CWE-{f.cwe_id} ↗
                            </a>
                          ) : <p className="font-mono text-[#64748b]">—</p>}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>

      {/* Scan metadata footer */}
      {latestScan && (
        <p className="text-xs text-[#64748b] text-right">
          Last scan: {new Date(latestScan.completed_at || latestScan.started_at).toLocaleString()} ·
          Target: <span className="font-mono">{latestScan.target_url}</span> ·
          Status: <span className={scanStatus === "COMPLETED" ? "text-green-400" : scanStatus === "FAILED" ? "text-red-400" : "text-yellow-400"}>{latestScan.status}</span>
        </p>
      )}
    </div>
  );
}
