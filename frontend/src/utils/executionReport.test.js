import test from "node:test";
import assert from "node:assert/strict";
import { buildPrintableExecutionReport, escapeHtml, getDetailedFindingCount, getFindingDetails, getFindingIdentifier, getFindingLocation, getSastSummaryCount, normalizeSeverity } from "./executionReport.js";
const report={execution:{id:17,status:"COMPLETED"},scans:{sast:{total_issues:2}},findings:{sast:[{severity:"MAJOR",rule:"css:S4666",file_path:"styles/style.css",line_number:19,message:"Duplicate selector html"},{severity:"MAJOR",rule:"css:S4666",file_path:"styles/style.css",line_number:31,message:"Duplicate selector h1"}],dependency:[],iac:[],image:[{severity:"HIGH",vulnerability_id:"CVE-1",package_name:"pkg"}],dast:[{severity:"MEDIUM",alert:"<script>",endpoint:"/"}]},counts:{bySeverity:{HIGH:3,MEDIUM:1}},limitations:{sastDetails:null}};
test("normalizes severities",()=>{assert.equal(normalizeSeverity("major"),"HIGH");assert.equal(normalizeSeverity("minor"),"MEDIUM");assert.equal(normalizeSeverity("other"),"UNKNOWN");});
test("includes linked SAST details once while showing its summary separately",()=>{assert.equal(getDetailedFindingCount(report),4);assert.equal(getSastSummaryCount(report),2);});
test("maps linked SAST rule, path, line, message, and normalized severity",()=>{const finding=report.findings.sast[0];assert.equal(getFindingIdentifier(finding),"css:S4666");assert.equal(getFindingLocation(finding),"styles/style.css:19");assert.equal(getFindingDetails(finding),"Duplicate selector html");assert.equal(normalizeSeverity(finding.severity),"HIGH");});
test("escapes HTML export findings",()=>{assert.equal(escapeHtml('<x>'),"&lt;x&gt;");const html=buildPrintableExecutionReport(report);assert.ok(html.includes("&lt;script&gt;"));assert.ok(!html.includes("<script>"));});
test("labels SAST summary as context without double-counting",()=>{const html=buildPrintableExecutionReport(report);assert.match(html,/4 detailed findings/);assert.match(html,/SAST summary \(separate context\)/);assert.match(html,/css:S4666/);assert.match(html,/styles\/style\.css:19/);assert.match(html,/Duplicate selector html/);});
// Module 12 report additions (execution 123 shape).
import { formatDuration, engineLabel, getStageRows, getSastStatusText, getCleanPackagesText, getKubernetesSummary, shortCommit } from "./executionReport.js";
import { executionScanData } from "./executionScan.js";
const r123 = {
  execution: { id: 123, status: "COMPLETED", triggered_by: "webhook" },
  report: { id: "CSR-123-abcdefabcdef", generatedAt: "2026-11-28T10:00:00.000Z" },
  source: { repository: "https://github.com/o/python-clean", branch: "main", commit: "a".repeat(40), message: "ci: retrigger" },
  timing: { durationMs: 35328 },
  stages: [{ stage: "SAST", result: "PASSED", durationMs: 6571 }, { stage: "Deploy", result: "PASSED", durationMs: 18442, durationDerived: true }, { stage: "IaC", result: "PASSED", durationMs: 2726 }],
  engines: { SAST: { name: "ml-sast-v3-ensemble", version: "3.0.0", modelSha256: "f28cc42baae8" }, IaC: { name: "Trivy config", version: null, versionNote: "not recorded for this stage" } },
  gateRules: { note: "Current server configuration", rules: [{ stage: "Dependency", blocks: "blocks CRITICAL always; HIGH when a fix is available", why: "w" }] },
  scans: { sast: { status: "COMPLETED", total_issues: 0 }, dependency: { status: "COMPLETED" } },
  findings: { sast: [], dependency: [], iac: [], image: [], dast: [] },
  inventory: { dependencyClean: [{ pkg_name: "Flask-WTF", pkg_version: "1.2.2" }, { pkg_name: "waitress", pkg_version: "3.0.2" }] },
  limitations: { sastDetails: "No findings" },
  kubernetes: { admission: { status: "passed", namespace: "cloudsentinel-p-29", violations: 0 }, live: { status: "observed", compliance: { score: 100, pass: 7, fail: 0, evaluated: 7 } } },
  counts: { bySeverity: {} },
};
test("durations and engine labels", () => {
  assert.equal(formatDuration(128), "128 ms"); assert.equal(formatDuration(6571), "6.6 s"); assert.equal(formatDuration(95000), "1 min 35 s"); assert.equal(formatDuration(null), "—");
  assert.equal(engineLabel(r123.engines.SAST), "ml-sast-v3-ensemble 3.0.0 (model f28cc42baae8)");
  assert.equal(engineLabel(r123.engines.IaC), "Trivy config, version not recorded for this stage");
  assert.equal(engineLabel(null), "—");
});
test("stage rows carry result, duration and engine", () => {
  const rows = getStageRows(r123);
  assert.equal(rows[0].engine, "ml-sast-v3-ensemble 3.0.0 (model f28cc42baae8)");
  assert.equal(rows[1].duration, "18.4 s (derived)");
  assert.match(rows[1].engine, /Kyverno/);
});
test("clean SAST scan reads No findings; clean packages are labelled, not findings", () => {
  assert.equal(getSastStatusText(r123), "No findings. The SAST scan completed with 0 issues.");
  assert.doesNotMatch(getSastStatusText(r123), /legacy scan_results/);
  assert.equal(getCleanPackagesText(r123), "2 packages scanned with no known vulnerabilities (not findings): Flask-WTF 1.2.2, waitress 3.0.2.");
  assert.equal(getFindingIdentifier({}), "No advisory ID");
  const dep = executionScanData(r123, "dependency");
  assert.equal(dep.packages.length, 2); assert.equal(dep.vulnerable.length, 0);
});
test("Kubernetes summary separates deploy-time admission from live compliance", () => {
  const l = getKubernetesSummary(r123);
  assert.equal(l[0], "Admission at deploy time: passed in cloudsentinel-p-29, 0 policy violations.");
  assert.match(l[1], /100% — 7 passed, 0 failed of 7 evaluated/);
  assert.match(getKubernetesSummary({ ...r123, kubernetes: { admission: null, live: { status: "kyverno_not_installed" } } })[1], /not available \(kyverno_not_installed\)/);
  assert.equal(shortCommit("a".repeat(40)), "aaaaaaaaaaaa"); assert.equal(shortCommit("zz"), null);
});
test("HTML export contains run metadata, stages, rules, report ID and escapes values", () => {
  const html = buildPrintableExecutionReport({ ...r123, source: { ...r123.source, message: "<img src=x onerror=1>" } });
  for (const s of ["CSR-123-abcdefabcdef", "https://github.com/o/python-clean", "main", "a".repeat(40), "35.3 s", "Gate rules in force", "blocks CRITICAL always", "Kyverno compliance", "ml-sast-v3-ensemble 3.0.0", "No findings. The SAST scan", "Flask-WTF 1.2.2"]) assert.ok(html.includes(s), s);
  assert.ok(!html.includes("<img src=x"));
});

test("HTML export labels the staging URL and gives the port-forward command", () => {
  const html = buildPrintableExecutionReport({ ...r123, execution: { ...r123.execution, project_id: 29 }, deployment: { staging_url: "http://192.168.49.2:32559", app_name: "test1" } });
  assert.ok(html.includes("http://192.168.49.2:32559 (reachable from the WSL host only)"));
  assert.ok(html.includes("kubectl --context minikube -n cloudsentinel-p-29 port-forward service/test1 8080:80"));
});
