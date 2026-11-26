// Module 9 / SRS FR-20: Secrets Management. Real data only: Kubernetes secret METADATA from the project's
// namespaces on the configured context (values are never sent by the API and are always shown masked), plus a
// rotation policy and expiry date per secret stored by CloudSentinel (migration 025). There is no rotate button:
// nothing on this stack rotates a secret value from the UI; the rotation card shows the real status instead.
import { useEffect, useState } from "react";
import PageHeader from "../components/PageHeader";
import api from "../lib/api";

const EXPIRY_STYLE = { EXPIRED: "bg-red-500/15 text-red-300", EXPIRING_SOON: "bg-yellow-500/15 text-yellow-300", OK: "bg-green-500/15 text-green-300", NOT_SET: "bg-slate-500/15 text-slate-300" };
const ROTATION_STYLE = { OVERDUE: "text-red-300", WITHIN_POLICY: "text-green-300", NO_POLICY: "text-slate-400", UNKNOWN: "text-slate-400" };
const tableClass = "w-full text-sm [&_td]:p-3 [&_td]:align-top [&_th]:p-3 [&_tr]:border-b [&_tr]:border-[#1e2d4a]";
const errText = (e, fallback) => e?.response?.data?.error || fallback;
const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");

function PolicyEditor({ secret, projectId, onSaved }) {
  const [rotationDays, setRotationDays] = useState(secret.policy?.rotationDays ?? "");
  const [expiresAt, setExpiresAt] = useState(secret.policy?.expiresAt ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const save = async (clear = false) => {
    setBusy(true); setError("");
    try {
      await api.put(`/secrets/projects/${projectId}/policies`, {
        namespace: secret.namespace, name: secret.name,
        rotationDays: clear || rotationDays === "" ? null : Number(rotationDays),
        expiresAt: clear || expiresAt === "" ? null : expiresAt,
      });
      onSaved();
    } catch (e) { setError(errText(e, "Policy could not be saved")); }
    finally { setBusy(false); }
  };
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs">Rotate every
          <input className="input w-20 ml-1 inline-block" type="number" min="1" max="3650" value={rotationDays} onChange={(e) => setRotationDays(e.target.value)} aria-label={`Rotation days for ${secret.name}`} /> days
        </label>
        <label className="text-xs">Expires
          <input className="input w-40 ml-1 inline-block" type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} aria-label={`Expiry date for ${secret.name}`} />
        </label>
      </div>
      <div className="flex gap-2">
        <button className="primary-btn text-xs" disabled={busy} onClick={() => save(false)}>Save policy</button>
        {secret.policy && <button className="secondary-btn text-xs" disabled={busy} onClick={() => save(true)}>Clear</button>}
      </div>
      {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
    </div>
  );
}

export default function SecretsManagement() {
  const [projects, setProjects] = useState([]);
  const [project, setProject] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(null);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let active = true;
    api.get("/projects").then((r) => { if (active) setProjects(r.data.projects || []); }).catch(() => { if (active) setError("Unable to load authorized projects."); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    setData(null); setEditing(null);
    if (!project) return () => { active = false; };
    setLoading(true); setError("");
    api.get(`/secrets/projects/${project}`, { timeout: 30000 })
      .then((r) => { if (active) setData(r.data); })
      .catch((e) => { if (active) setError(errText(e, "Secrets inventory unavailable.")); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [project, reload]);

  const counts = (data?.secrets || []).reduce((c, s) => ({ ...c, [s.expiry.status]: (c[s.expiry.status] || 0) + 1, overdue: c.overdue + (s.rotation.status === "OVERDUE" ? 1 : 0) }), { overdue: 0 });

  return (
    <div className="space-y-6">
      <PageHeader title="Secrets Management" subtitle="Kubernetes secret metadata for the selected project. Values are never read or shown." />
      <label className="block">Project <select className="ml-3 bg-[#0b1220] border border-[#1e2d4a] rounded p-2" value={project} onChange={(e) => setProject(e.target.value)}>
        <option value="">Select project</option>{projects.map((p) => <option key={p.id} value={p.id}>{p.name} (#{p.id})</option>)}</select></label>
      {error && <p role="alert">{error}</p>}
      {loading && <p role="status">Reading Kubernetes secrets…</p>}
      {!project && !loading && <div className="card p-5">Select a project to list the secrets in its namespace.</div>}

      {data && (
        <>
          <div className="card p-5 space-y-1">
            <h3 className="font-bold">{data.status === "observed" ? `Connected • ${data.context}` : data.status === "not_deployed" ? "Not deployed" : "Not connected"}</h3>
            {data.reason && <p>{data.reason}</p>}
            {data.status === "not_deployed" && <p>The project namespace does not exist on {data.context} yet, so it has no secrets.</p>}
            {data.namespaces?.length > 0 && <p>Namespaces: {data.namespaces.join(", ")}</p>}
            <p className="text-sm text-slate-400">Your access: {data.role === "admin" ? "platform admin" : "project owner"}. Only the project owner and platform admins can view these secrets or set policies. Read-only snapshot observed {fmt(data.observedAt)}.</p>
            {data.status === "observed" && <p className="text-sm">Secrets: {data.secrets.length} • Expired: {counts.EXPIRED || 0} • Expiring within {data.expiryWarnDays} days: {counts.EXPIRING_SOON || 0} • Rotation overdue: {counts.overdue}</p>}
          </div>

          {data.status === "observed" && data.policiesAvailable === false && (
            <div className="card p-4 border border-yellow-600/50 text-yellow-200">Rotation policies and expiry dates are unavailable: migration 025 is not applied (<span className="font-mono">npm run migrate:secrets</span>).</div>
          )}

          {data.status === "observed" && (
            <section className="card p-5 overflow-auto">
              <h3 className="font-bold mb-2">Secrets</h3>
              {!data.secrets.length ? <p>No Kubernetes Secrets in {data.namespaces.join(", ")}.</p> : (
                <table className={tableClass}>
                  <thead><tr className="text-left text-slate-400"><th>Namespace</th><th>Name</th><th>Source</th><th>Keys</th><th>Value</th><th>Last changed</th><th>Rotation</th><th>Expiry</th><th>Policy</th></tr></thead>
                  <tbody>{data.secrets.map((s) => {
                    const key = `${s.namespace}/${s.name}`;
                    return (
                      <tr key={key}>
                        <td>{s.namespace}</td>
                        <td className="font-mono break-all">{s.name}<div className="text-xs text-slate-500">{s.type}</div></td>
                        <td>{s.source}</td>
                        <td>{s.keysCount}</td>
                        <td className="font-mono" aria-label="masked value">{s.value}</td>
                        <td>{fmt(s.lastChangedAt)}{s.ageDays !== null && <div className="text-xs text-slate-500">{s.ageDays} day(s) ago</div>}</td>
                        <td className={ROTATION_STYLE[s.rotation.status] || ""}>{s.rotation.text}</td>
                        <td><span className={`px-2 py-0.5 rounded text-xs ${EXPIRY_STYLE[s.expiry.status] || ""}`}>{s.expiry.text}</span>{s.policy?.expiresAt && <div className="text-xs text-slate-500">{s.policy.expiresAt}</div>}</td>
                        <td>{data.canEditPolicies
                          ? (editing === key ? <PolicyEditor secret={s} projectId={project} onSaved={() => { setEditing(null); setReload((n) => n + 1); }} />
                            : <button className="secondary-btn text-xs" onClick={() => setEditing(key)}>{s.policy ? "Edit policy" : "Set policy"}</button>)
                          : <span className="text-xs text-slate-500">unavailable</span>}</td>
                      </tr>
                    );
                  })}</tbody>
                </table>
              )}
              <p className="text-xs text-slate-500 mt-3">"Last changed" is the latest write time recorded by Kubernetes for the secret object. An alert is raised on the Monitoring screen when an expiry date is within {data.expiryWarnDays} days or has passed.</p>
            </section>
          )}

          <section className="card p-5 space-y-2">
            <h3 className="font-bold">Rotation</h3>
            <p className={data.rotation?.available ? "" : "text-yellow-200"}>{data.rotation?.text}</p>
            <p className="text-sm">Command: <span className="font-mono break-all">{data.rotation?.command}</span></p>
          </section>
        </>
      )}
    </div>
  );
}
