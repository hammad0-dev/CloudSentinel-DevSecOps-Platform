import { normalizeSeverity } from "./executionReport.js";

export function getExecutionResultsLink(name, projectId, executionId) {
  const query = `?projectId=${encodeURIComponent(projectId)}&executionId=${encodeURIComponent(executionId)}`;
  const paths = { SAST: `/projects/${projectId}/sast`, "Dependency / SBOM": "/dependencies", IaC: "/iac", "Container image": `/projects/${projectId}/image`, DAST: `/projects/${projectId}/dast` };
  return paths[name] ? paths[name] + query : null;
}

export function executionScanData(report, kind) {
  const scan = report.scans?.[kind] || null;
  const findings = report.findings?.[kind] || [];
  if (kind === "sast") return {
    summary: { critical: scan?.critical || 0, major: scan?.high || 0, minor: scan?.medium || 0, total: scan?.total_issues || 0 },
    vulnerabilities: findings.map(f => ({ ...f, severity: ({ HIGH: "MAJOR", MEDIUM: "MINOR" })[normalizeSeverity(f.severity)] || f.severity })),
    sonarMetrics: null, lastScan: scan?.completed_at || scan?.started_at,
  };
  if (kind === "dependency") {
    // Clean packages (no known vulnerability) come back separately as inventory, not as findings.
    const packages = [...findings, ...(report.inventory?.dependencyClean || []).map(p => ({ ...p, cve_id: null, severity: "NONE" }))];
    const licenses = new Map();
    packages.forEach(f => licenses.set(f.license || "Unknown", (licenses.get(f.license || "Unknown") || 0) + 1));
    return { latestScan: scan, packages, vulnerable: findings.filter(f => f.cve_id), licenses: [...licenses].map(([name, value]) => ({ name, value })) };
  }
  return { latestScan: scan, findings, summary: { ...scan, total: scan?.total_findings || 0 }, target_url: scan?.target_url || "" };
}

// Historical links always read the execution's saved evidence, never the latest scan.
export function executionResultsApi(api, projectId, executionId) {
  if (!executionId) return api;
  return { ...api, get: async (url, options) => {
    const match = url.match(/^\/(sast|dependencies|iac|dast)\/\d+$/);
    if (!match) return api.get(url, options);
    const response = await api.get(`/reports/projects/${projectId}/executions/${executionId}`);
    return { ...response, data: executionScanData(response.data, match[1] === "dependencies" ? "dependency" : match[1]) };
  } };
}

// Container image results page: the image scan and its vulnerabilities saved with one execution.
export function imageScanView(report) {
  const scan = report?.scans?.image || null, items = report?.findings?.image || [];
  const rule = (report?.gateRules?.rules || []).find(r => r.stage === "Container image") || null;
  const bySeverity = {};
  for (const v of items) { const s = normalizeSeverity(v.severity); bySeverity[s] = (bySeverity[s] || 0) + 1; }
  const fixable = items.filter(v => v.fixed_version && String(v.fixed_version).trim()).length;
  const stage = (report?.stages || []).find(s => s.stage === "Container image") || null;
  return { scan, items, rule, bySeverity, fixable, result: stage?.result || null, imageTag: scan?.image_tag || report?.deployment?.image_tag || null };
}
