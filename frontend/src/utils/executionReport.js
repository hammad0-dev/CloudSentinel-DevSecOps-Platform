export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"];

export function normalizeSeverity(value) {
  const upper = String(value || "UNKNOWN").toUpperCase();
  if (upper === "MAJOR") return "HIGH";
  if (upper === "MINOR") return "MEDIUM";
  return SEVERITIES.includes(upper) ? upper : "UNKNOWN";
}

export function getDetailedFindingGroups(report) {
  const findings = report?.findings || {};
  return [["SAST", findings.sast || []], ["Dependency / SBOM", findings.dependency || []], ["IaC", findings.iac || []], ["Container image", findings.image || []], ["DAST", findings.dast || []], ["Active DAST", findings.activeDast || []]];
}

export function getDetailedFindingCount(report) {
  return getDetailedFindingGroups(report).reduce((total, [, findings]) => total + findings.length, 0);
}

export function getSastSummaryCount(report) {
  return Number(report?.scans?.sast?.total_issues || 0);
}

export function getFindingIdentifier(finding) {
  return finding?.rule || finding?.vulnerability_id || finding?.cve_id || finding?.misconfig_id || finding?.alert || "Finding";
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

export function buildPrintableExecutionReport(report) {
  const execution = report?.execution || {}, deployment = report?.deployment || {}, counts = report?.counts || {};
  const severityCells = SEVERITIES.map((severity) => `<li><strong>${severity}:</strong> ${Number(counts.bySeverity?.[severity] || 0)}</li>`).join("");
  const findingRows = getDetailedFindingGroups(report).flatMap(([scanner, findings]) => findings.map((finding) => `<tr><td>${escapeHtml(scanner)}</td><td>${escapeHtml(normalizeSeverity(finding.severity))}</td><td>${escapeHtml(getFindingIdentifier(finding))}</td><td>${escapeHtml(getFindingLocation(finding) || "-")}</td><td>${escapeHtml(getFindingDetails(finding) || "-")}</td></tr>`)).join("");
  const sastTotal = getSastSummaryCount(report);
  return `<!doctype html><html><head><meta charset="utf-8"><title>CloudSentinel Execution #${escapeHtml(execution.id)}</title><style>body{font-family:system-ui,sans-serif;color:#172033;margin:32px}h1,h2{margin-bottom:8px}.muted{color:#526078}.card{border:1px solid #cbd5e1;border-radius:8px;padding:16px;margin:16px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #cbd5e1;padding:8px;text-align:left}th{background:#eff6ff}</style></head><body><h1>CloudSentinel execution report</h1><p class="muted">Execution #${escapeHtml(execution.id)} · ${escapeHtml(execution.status)} · Generated ${escapeHtml(new Date().toLocaleString())}</p><div class="card"><h2>Deployment</h2><p><strong>Staging URL:</strong> ${escapeHtml(deployment.staging_url || "Not deployed")}</p><p><strong>Image:</strong> ${escapeHtml(deployment.image_tag || report?.scans?.image?.image_tag || "Unavailable")}</p></div><div class="card"><h2>Execution-linked detailed findings</h2><p>${getDetailedFindingCount(report)} detailed findings, including linked SAST details when available.</p><ul>${severityCells}</ul></div><div class="card"><h2>SAST summary (separate context)</h2><p>${escapeHtml(report?.limitations?.sastDetails || `${sastTotal} SAST summary findings are included in the linked detailed total and shown separately for context.`)}</p></div><div class="card"><h2>Detailed findings</h2><table><thead><tr><th>Scanner</th><th>Severity</th><th>Rule / CVE</th><th>Location or package</th><th>Details</th></tr></thead><tbody>${findingRows || "<tr><td colspan=\"4\">No execution-linked detailed findings.</td></tr>"}</tbody></table></div></body></html>`;
}

export function downloadReport(content, mimeType, filename) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob), anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url);
}
