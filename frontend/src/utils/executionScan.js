import { normalizeSeverity } from "./executionReport.js";

export function getExecutionResultsLink(name, projectId, executionId) {
  const query = `?projectId=${encodeURIComponent(projectId)}&executionId=${encodeURIComponent(executionId)}`;
  const paths = { SAST: `/projects/${projectId}/sast`, "Dependency / SBOM": "/dependencies", IaC: "/iac", DAST: `/projects/${projectId}/dast` };
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
    const licenses = new Map();
    findings.forEach(f => licenses.set(f.license || "Unknown", (licenses.get(f.license || "Unknown") || 0) + 1));
    return { latestScan: scan, packages: findings, vulnerable: findings.filter(f => f.cve_id), licenses: [...licenses].map(([name, value]) => ({ name, value })) };
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
