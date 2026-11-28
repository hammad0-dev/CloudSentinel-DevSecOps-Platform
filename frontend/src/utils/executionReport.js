export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"];

export function normalizeSeverity(value) {
  const upper = String(value || "UNKNOWN").toUpperCase();
  if (upper === "MAJOR") return "HIGH";
  if (upper === "MINOR") return "MEDIUM";
  return SEVERITIES.includes(upper) ? upper : "UNKNOWN";
}

export function getDetailedFindingGroups(report) {
  const findings = report?.findings || {};
  return [["SAST", findings.sast || []], ["Dependency / SBOM", findings.dependency || []], ["IaC", findings.iac || []], ["Container image", findings.image || []], ["DAST", findings.dast || []]];
}

export function getDetailedFindingCount(report) {
  return getDetailedFindingGroups(report).reduce((total, [, findings]) => total + findings.length, 0);
}

export function getSastSummaryCount(report) {
  return Number(report?.scans?.sast?.total_issues || 0);
}

export function getFindingIdentifier(finding) {
  return finding?.rule || finding?.vulnerability_id || finding?.cve_id || finding?.misconfig_id || finding?.alert || "No advisory ID";
}

export function getFindingLocation(finding) {
  if (finding?.file_path) {
    return finding.line_number === null || finding.line_number === undefined || finding.line_number === ""
      ? finding.file_path
      : `${finding.file_path}:${finding.line_number}`;
  }
  return finding?.package_name || finding?.pkg_name || finding?.config_file || finding?.endpoint || "";
}

export function getFindingDetails(finding) {
  return finding?.message || finding?.title || finding?.description || finding?.solution || finding?.resolution || "";
}
export function escapeHtml(value) {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\"/g, "&quot;").replace(/'/g, "&#39;");
}

export function formatDuration(ms) {
  const n = Number(ms);
  if (ms === null || ms === undefined || !Number.isFinite(n) || n < 0) return "—";
  if (n < 1000) return `${Math.round(n)} ms`;
  const sec = n / 1000;
  if (sec < 60) return `${sec.toFixed(1)} s`;
  return `${Math.floor(sec / 60)} min ${Math.round(sec % 60)} s`;
}

const ENGINE_KEY = { SAST: "SAST", Dependency: "Dependency", IaC: "IaC", "Container image": "Container image", DAST: "DAST" };

export function engineLabel(engine) {
  if (!engine) return "—";
  const name = engine.name || engine.engine || "Unknown engine";
  if (engine.version) return `${name} ${engine.version}${engine.modelSha256 ? ` (model ${engine.modelSha256})` : ""}`;
  return engine.versionNote ? `${name}, version ${engine.versionNote}` : `${name}, version not recorded`;
}

// One row per pipeline stage: result, duration and the engine that ran it.
export function getStageRows(report) {
  const engines = report?.engines || {};
  return (report?.stages || []).map((s) => ({ ...s, duration: `${formatDuration(s.durationMs)}${s.durationDerived ? " (derived)" : ""}`, engine: ENGINE_KEY[s.stage] ? engineLabel(engines[ENGINE_KEY[s.stage]]) : s.stage === "Deploy" ? "kubectl + Kyverno admission (server dry-run)" : "—" }));
}

export function getSastStatusText(report) {
  const note = report?.limitations?.sastDetails;
  if (note === "No findings") return "No findings. The SAST scan completed with 0 issues.";
  if (note) return note;
  const sast = getSastSummaryCount(report);
  return `Execution-linked SAST details are available below. The ${sast} SAST summary findings are already included in the ${getDetailedFindingCount(report)} linked detailed findings and are not counted again.`;
}

export function getCleanPackagesText(report) {
  const clean = report?.inventory?.dependencyClean || [];
  if (!clean.length) return "";
  const names = clean.slice(0, 20).map((p) => `${p.pkg_name}${p.pkg_version ? ` ${p.pkg_version}` : ""}`).join(", ");
  return `${clean.length} package${clean.length === 1 ? "" : "s"} scanned with no known vulnerabilities (not findings): ${names}${clean.length > 20 ? ", …" : ""}.`;
}

export function shortCommit(commit) {
  return typeof commit === "string" && /^[a-f0-9]{40}$/.test(commit) ? commit.slice(0, 12) : null;
}

export function getKubernetesSummary(report) {
  const admission = report?.kubernetes?.admission, live = report?.kubernetes?.live;
  const lines = [];
  if (!admission) lines.push("Admission: no deployment in this execution.");
  else if (admission.status === "not_recorded") lines.push("Admission: not recorded for this deployment.");
  else lines.push(`Admission at deploy time: ${admission.status === "passed" ? "passed" : "rejected"}${admission.namespace ? ` in ${admission.namespace}` : ""}${Number.isFinite(admission.violations) ? `, ${admission.violations} policy violation${admission.violations === 1 ? "" : "s"}` : ""}.`);
  if (!live) lines.push("Kyverno compliance (live): not loaded.");
  else if (live.status !== "observed") lines.push(`Kyverno compliance (live): not available (${live.reason || live.status}).`);
  else if (live.compliance?.score === null || live.compliance?.score === undefined) lines.push("Kyverno compliance (live): no policy results for this namespace yet.");
  else lines.push(`Kyverno compliance (live, at report generation): ${live.compliance.score}% — ${live.compliance.pass} passed, ${live.compliance.fail} failed of ${live.compliance.evaluated} evaluated.`);
  return lines;
}

export function buildPrintableExecutionReport(report) {
  const execution = report?.execution || {}, deployment = report?.deployment || {}, counts = report?.counts || {}, source = report?.source || {}, meta = report?.report || {};
  const severityCells = SEVERITIES.map((severity) => `<li><strong>${severity}:</strong> ${Number(counts.bySeverity?.[severity] || 0)}</li>`).join("");
  const findingRows = getDetailedFindingGroups(report).flatMap(([scanner, findings]) => findings.map((finding) => `<tr><td>${escapeHtml(scanner)}</td><td>${escapeHtml(normalizeSeverity(finding.severity))}</td><td>${escapeHtml(getFindingIdentifier(finding))}</td><td>${escapeHtml(getFindingLocation(finding) || "-")}</td><td>${escapeHtml(getFindingDetails(finding) || "-")}</td></tr>`)).join("");
  const stageRows = getStageRows(report).map((s) => `<tr><td>${escapeHtml(s.stage)}</td><td>${escapeHtml(s.result)}</td><td>${escapeHtml(s.duration)}</td><td>${escapeHtml(s.engine)}</td></tr>`).join("");
  const ruleRows = (report?.gateRules?.rules || []).map((r) => `<tr><td>${escapeHtml(r.stage)}</td><td>${escapeHtml(r.blocks)}</td><td>${escapeHtml(r.why)}</td></tr>`).join("");
  const clean = getCleanPackagesText(report);
  const row = (k, v) => `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v ?? "—")}</td></tr>`;
  return `<!doctype html><html><head><meta charset="utf-8"><title>CloudSentinel Execution #${escapeHtml(execution.id)}</title><style>body{font-family:system-ui,sans-serif;color:#172033;margin:32px}h1,h2{margin-bottom:8px}.muted{color:#526078}.card{border:1px solid #cbd5e1;border-radius:8px;padding:16px;margin:16px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #cbd5e1;padding:8px;text-align:left;vertical-align:top}th{background:#eff6ff}</style></head><body><h1>CloudSentinel execution report</h1><p class="muted">Execution #${escapeHtml(execution.id)} · ${escapeHtml(execution.status)} · Report ${escapeHtml(meta.id || "—")} · Generated ${escapeHtml(meta.generatedAt || new Date().toISOString())}</p>`
    + `<div class="card"><h2>Run</h2><table>${row("Repository", source.repository)}${row("Branch", source.branch)}${row("Commit", source.commit || source.note)}${row("Commit message", source.message)}${row("Trigger", execution.triggered_by)}${row("Started", execution.started_at)}${row("Completed", execution.completed_at)}${row("Duration", formatDuration(report?.timing?.durationMs))}</table></div>`
    + `<div class="card"><h2>Stages</h2><table><thead><tr><th>Stage</th><th>Result</th><th>Duration</th><th>Engine and version</th></tr></thead><tbody>${stageRows || "<tr><td colspan=\"4\">No stage records.</td></tr>"}</tbody></table></div>`
    + `<div class="card"><h2>Gate rules in force</h2><p class="muted">${escapeHtml(report?.gateRules?.note || "")}</p><table><thead><tr><th>Stage</th><th>Blocks</th><th>Why</th></tr></thead><tbody>${ruleRows}</tbody></table></div>`
    + `<div class="card"><h2>Kubernetes and compliance</h2><ul>${getKubernetesSummary(report).map((l) => `<li>${escapeHtml(l)}</li>`).join("")}</ul></div>`
    + `<div class="card"><h2>Deployment</h2><p><strong>Staging URL:</strong> ${escapeHtml(deployment.staging_url || "Not deployed")}</p><p><strong>Image:</strong> ${escapeHtml(deployment.image_tag || report?.scans?.image?.image_tag || "Unavailable")}</p></div>`
    + `<div class="card"><h2>Execution-linked detailed findings</h2><p>${getDetailedFindingCount(report)} detailed findings, including linked SAST details when available.</p><ul>${severityCells}</ul></div>`
    + `<div class="card"><h2>SAST summary (separate context)</h2><p>${escapeHtml(getSastStatusText(report))}</p></div>`
    + `<div class="card"><h2>Detailed findings</h2><table><thead><tr><th>Scanner</th><th>Severity</th><th>Rule / CVE</th><th>Location or package</th><th>Details</th></tr></thead><tbody>${findingRows || "<tr><td colspan=\"5\">No execution-linked detailed findings.</td></tr>"}</tbody></table>${clean ? `<p class="muted">${escapeHtml(clean)}</p>` : ""}</div></body></html>`;
}

export function downloadReport(content, mimeType, filename) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob), anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url);
}
