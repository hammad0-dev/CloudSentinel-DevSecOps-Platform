import { useCallback, useEffect, useRef, useState } from "react";
import api from "../lib/api";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import { alertMatches, alertParams, logParams, logSources } from "../utils/monitoringFilters";

// Module 11 FE-3/FE-5: live security alerts (SSE with polling fallback), triage and log search.
const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const STATUSES = ["OPEN,ACKNOWLEDGED", "OPEN", "ACKNOWLEDGED", "RESOLVED", ""];
const STATUS_LABEL = { "OPEN,ACKNOWLEDGED": "Active", OPEN: "Open", ACKNOWLEDGED: "Acknowledged", RESOLVED: "Resolved", "": "All" };
const RANGES = { "15m": 15, "1h": 60, "6h": 360, "24h": 1440 };
const POLL_MS = 15000;
const RULE_TITLES = {
  failed_login_burst: "Repeated failed logins",
  webhook_signature_burst: "Webhook invalid-signature burst",
  pipeline_trigger_anomaly: "Unusual pipeline trigger rate",
  k8s_pod_restart_loop: "Pod restart loop",
  kyverno_denied_spike: "Kyverno policy-denied spike",
  secret_expiring: "Secret expiring or expired",
};
const BORDER = { CRITICAL: "border-l-red-600", HIGH: "border-l-orange-500", MEDIUM: "border-l-yellow-500", LOW: "border-l-blue-500" };

const errText = (e, fallback) => e?.response?.data?.error || e?.message || fallback;
const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");

function summary(alert) {
  const d = alert.details || {};
  switch (alert.rule) {
    case "failed_login_burst": return `${d.count} failed logins for ${d.account ? `account ${d.account}` : `IP ${d.ip}`}`;
    case "webhook_signature_burst": return `${d.count} invalid webhook signatures${d.repositories?.length ? ` (${d.repositories.join(", ")})` : ""}`;
    case "pipeline_trigger_anomaly": return `${d.count} pipeline runs in 10 min for project ${alert.project_id ?? "?"}`;
    case "k8s_pod_restart_loop": return `${d.namespace}/${d.pod} (${d.container}) restarted ${d.restarts}x${d.reason ? ` — ${d.reason}` : ""}`;
    case "kyverno_denied_spike": return `${d.count} policy violations in ${d.namespace}${d.policies?.length ? ` (${d.policies.join(", ")})` : ""}`;
    default: return d.description || alert.rule;
  }
}

// Reads the SSE stream with fetch so the JWT travels in the Authorization header, not the URL.
async function readStream(signal, onOpen, onAlert) {
  const res = await fetch(`${api.defaults.baseURL}/monitoring/stream`, {
    headers: { Authorization: `Bearer ${localStorage.getItem("cloudsentinel_token") || ""}` },
    signal,
  });
  if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
  onOpen();
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) throw new Error("stream closed");
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const data = block.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).join("\n");
      if (block.startsWith("event: alert") && data) {
        try { onAlert(JSON.parse(data)); } catch { /* ignore malformed frame */ }
      }
    }
  }
}

function LogLines({ lines }) {
  if (!lines?.length) return <p className="text-sm text-[#64748b]">No log lines.</p>;
  return (
    <div className="max-h-80 overflow-auto font-mono text-xs space-y-1">
      {lines.map((l, i) => (
        <div key={i} className="border-t border-[#1e2d4a] pt-1 break-all">
          <span className="text-[#64748b]">{fmt(l.ts)} </span>
          <span className="text-[#94a3b8]">[{l.labels?.source}{l.labels?.namespace ? ` ${l.labels.namespace}` : ""}] </span>
          {l.line}
        </div>
      ))}
    </div>
  );
}

export default function MonitoringAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("OPEN,ACKNOWLEDGED");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [mode, setMode] = useState("connecting");
  const [selected, setSelected] = useState(null);
  const [context, setContext] = useState(null);
  const [contextError, setContextError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [logQuery, setLogQuery] = useState({ source: "", q: "", range: "1h" });
  const [logResult, setLogResult] = useState(null);
  const [logError, setLogError] = useState("");
  const [logLoading, setLogLoading] = useState(false);
  const [projects, setProjects] = useState([]);
  const [project, setProject] = useState(""); // "" = all my projects
  const filtersRef = useRef({ severity, status, project });
  filtersRef.current = { severity, status, project };

  useEffect(() => {
    let active = true;
    api.get("/projects").then(({ data }) => { if (active) setProjects(data.projects || []); }).catch(() => {});
    return () => { active = false; };
  }, []);

  const load = useCallback(async () => {
    try {
      const { data } = await api.get("/monitoring/alerts", { params: alertParams({ severity, status, project }) });
      setAlerts(data.alerts || []);
      setError("");
    } catch (e) {
      setError(errText(e, "Failed to load alerts"));
    } finally {
      setLoading(false);
    }
  }, [severity, status, project]);

  useEffect(() => { setLoading(true); load(); }, [load]);
  // Log results belong to the previously selected project; clear them on change.
  useEffect(() => { setLogResult(null); setLogError(""); setSelected(null); }, [project]);

  const matches = (a) => alertMatches(a, filtersRef.current);

  // Live updates: SSE first, polling fallback, SSE retried every minute.
  useEffect(() => {
    let stopped = false;
    let pollTimer = null;
    let retryTimer = null;
    let controller = null;
    const startPolling = () => {
      setMode("polling");
      if (!pollTimer) pollTimer = setInterval(() => load(), POLL_MS);
    };
    const connect = () => {
      if (stopped) return;
      controller = new AbortController();
      readStream(
        controller.signal,
        () => {
          setMode("live");
          if (pollTimer) { clearInterval(pollTimer); pollTimer = null; load(); }
        },
        ({ alert }) => {
          setAlerts((prev) => {
            const rest = prev.filter((a) => a.id !== alert.id);
            return matches(alert) ? [alert, ...rest].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)) : rest;
          });
          setSelected((s) => (s && s.id === alert.id ? alert : s));
        }
      ).catch(() => {
        if (stopped) return;
        startPolling();
        retryTimer = setTimeout(connect, 60000);
      });
    };
    connect();
    return () => {
      stopped = true;
      controller?.abort();
      clearInterval(pollTimer);
      clearTimeout(retryTimer);
    };
  }, [load]);

  const openAlert = async (alert) => {
    setSelected(alert);
    setNote("");
    setContext(null);
    setContextError("");
    try {
      const { data } = await api.get(`/monitoring/alerts/${alert.id}/context`);
      setContext(data);
    } catch (e) {
      setContextError(errText(e, "Failed to load context"));
    }
  };

  const transition = async (next) => {
    if (!selected) return;
    setBusy(true);
    try {
      const { data } = await api.patch(`/monitoring/alerts/${selected.id}`, { status: next, note: note.trim() || undefined });
      setSelected(data.alert);
      setNote("");
      setAlerts((prev) => prev.map((a) => (a.id === data.alert.id ? data.alert : a)).filter(matches));
    } catch (e) {
      setContextError(errText(e, "Update failed"));
    } finally {
      setBusy(false);
    }
  };

  const searchLogs = async (e) => {
    e?.preventDefault();
    setLogLoading(true);
    setLogError("");
    try {
      const to = Date.now();
      const from = to - RANGES[logQuery.range] * 60000;
      const { data } = await api.get("/monitoring/logs", { params: logParams({ ...logQuery, project, from, to }) });
      setLogResult(data);
    } catch (err) {
      setLogResult(null);
      setLogError(errText(err, "Log search failed"));
    } finally {
      setLogLoading(false);
    }
  };

  const openCount = alerts.filter((a) => a.status === "OPEN").length;
  const modeLabel = mode === "live" ? "● Live" : mode === "polling" ? `○ Polling every ${POLL_MS / 1000}s` : "Connecting…";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Monitoring & Alerts"
        subtitle={loading ? "Loading…" : `${openCount} open alert${openCount === 1 ? "" : "s"}`}
        actions={<span className={`text-xs ${mode === "live" ? "text-green-500" : "text-[#64748b]"}`}>{modeLabel}</span>}
      />

      <div className="flex flex-wrap gap-3 items-center">
        <select className="input w-auto" value={project} onChange={(e) => { setProject(e.target.value); if (!logSources(e.target.value).includes(logQuery.source)) setLogQuery({ ...logQuery, source: "" }); }} aria-label="Project">
          <option value="">All my projects</option>
          {projects.map((p) => <option key={p.id} value={p.id}>{p.name} (#{p.id})</option>)}
        </select>
        <select className="input w-auto" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity filter">
          {SEVERITIES.map((s) => <option key={s} value={s}>{s || "All severities"}</option>)}
        </select>
        <select className="input w-auto" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status filter">
          {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
        </select>
        <button className="secondary-btn" onClick={load}>Refresh</button>
      </div>

      {error ? <div className="card p-4 text-red-500">{error}</div> : null}

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="space-y-2">
          {!loading && !alerts.length && !error ? <div className="card p-4 text-sm text-[#64748b]">No alerts match these filters{project ? ` for project #${project}` : ""}.</div> : null}
          {alerts.map((a) => (
            <button
              key={a.id}
              onClick={() => openAlert(a)}
              className={`card p-4 w-full text-left border-l-4 ${BORDER[a.severity] || "border-l-gray-500"} ${selected?.id === a.id ? "ring-1 ring-blue-500" : ""}`}
            >
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={a.severity} />
                <span className="font-semibold">{RULE_TITLES[a.rule] || a.rule}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-[#1e2d4a]">{a.status}</span>
                <span className="text-xs text-[#64748b]">{a.source} • {fmt(a.created_at)}</span>
              </div>
              <p className="text-sm mt-1">{summary(a)}</p>
            </button>
          ))}
        </div>

        <div className="card p-4 space-y-4 self-start">
          {!selected ? <p className="text-sm text-[#64748b]">Select an alert to investigate.</p> : (
            <>
              <div>
                <div className="flex items-center gap-2"><SeverityBadge severity={selected.severity} /><h3 className="font-bold">{RULE_TITLES[selected.rule] || selected.rule}</h3></div>
                <p className="text-sm mt-1">{summary(selected)}</p>
                <p className="text-xs text-[#64748b] mt-1">
                  #{selected.id} • {selected.status} • raised {fmt(selected.created_at)}
                  {selected.resolved_at ? ` • resolved ${fmt(selected.resolved_at)}` : ""}
                  {selected.project_id ? ` • project ${selected.project_id}` : ""}
                </p>
                <p className="text-xs text-[#64748b]">{selected.details?.description}</p>
              </div>

              {selected.note ? <pre className="text-xs whitespace-pre-wrap bg-[#0b1220] p-2 rounded">{selected.note}</pre> : null}

              {selected.status !== "RESOLVED" ? (
                <div className="space-y-2">
                  <textarea className="input w-full" rows={2} maxLength={2000} placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} />
                  <div className="flex gap-2">
                    {selected.status === "OPEN" ? <button className="secondary-btn" disabled={busy} onClick={() => transition("ACKNOWLEDGED")}>Acknowledge</button> : null}
                    <button className="primary-btn" disabled={busy} onClick={() => transition("RESOLVED")}>Resolve</button>
                  </div>
                </div>
              ) : null}

              {contextError ? <p className="text-sm text-red-500">{contextError}</p> : null}

              <div>
                <h4 className="font-semibold mb-1">Linked pipeline execution</h4>
                {!context ? <p className="text-sm text-[#64748b]">{contextError ? "—" : "Loading…"}</p> : context.execution ? (
                  <div className="text-sm">
                    #{context.execution.id} • {context.execution.status} • {context.execution.triggered_by || "—"}<br />
                    <span className="text-xs text-[#64748b]">
                      {fmt(context.execution.started_at)} → {fmt(context.execution.completed_at)}
                      {context.execution.stages_completed ? ` • stages: ${context.execution.stages_completed}` : ""}
                    </span>
                    {context.execution.failure_reason ? <p className="text-xs text-red-400">{context.execution.failure_reason}</p> : null}
                  </div>
                ) : <p className="text-sm text-[#64748b]">None linked.</p>}
              </div>

              <div>
                <h4 className="font-semibold mb-1">Context logs (±5 min)</h4>
                {context?.logs?.error ? <p className="text-sm text-yellow-500">{context.logs.error}</p> : null}
                {context ? <LogLines lines={context.logs?.lines} /> : null}
              </div>
            </>
          )}
        </div>
      </div>

      <form className="card p-4 space-y-3" onSubmit={searchLogs}>
        <h3 className="font-bold">Log search</h3>
        <p className="text-xs text-[#64748b]">{project ? `Scoped to project #${project}: backend logs carrying its projectId, or k8s logs from its namespace.` : "All projects you own (platform admins: all logs)."}</p>
        <div className="flex flex-wrap gap-2">
          <select className="input w-auto" value={logQuery.source} onChange={(e) => setLogQuery({ ...logQuery, source: e.target.value })} aria-label="Log source">
            <option value="">All sources</option>
            {logSources(project).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input className="input flex-1 min-w-[12rem]" maxLength={200} placeholder="Text (letters, digits, . , : ; @ / = + # ( ) [ ] - _)" value={logQuery.q} onChange={(e) => setLogQuery({ ...logQuery, q: e.target.value })} />
          <select className="input w-auto" value={logQuery.range} onChange={(e) => setLogQuery({ ...logQuery, range: e.target.value })} aria-label="Time range">
            {Object.keys(RANGES).map((r) => <option key={r} value={r}>Last {r}</option>)}
          </select>
          <button className="primary-btn" type="submit" disabled={logLoading}>{logLoading ? "Searching…" : "Search"}</button>
        </div>
        {logError ? <p className="text-sm text-red-500">{logError}</p> : null}
        {logResult ? (
          <>
            <p className="text-xs text-[#64748b] font-mono">{logResult.query} • {logResult.lines.length} lines</p>
            <LogLines lines={logResult.lines} />
          </>
        ) : null}
      </form>
    </div>
  );
}
