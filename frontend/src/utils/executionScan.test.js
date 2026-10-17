import test from "node:test";
import assert from "node:assert/strict";
import { getExecutionResultsLink, executionResultsApi, executionScanData } from "./executionScan.js";

test("links scanner results to the same project and execution", () => {
  for (const name of ["SAST", "Dependency / SBOM", "IaC", "DAST"]) {
    const url = new URL(getExecutionResultsLink(name, 8, 17), "http://localhost");
    assert.equal(url.searchParams.get("projectId"), "8");
    assert.equal(url.searchParams.get("executionId"), "17");
  }
  assert.equal(getExecutionResultsLink("IaC", 8, 17), "/iac?projectId=8&executionId=17");
});

test("historical result links read saved evidence instead of newer scan results", async () => {
  const calls = [];
  const scan = { id: 3, status: "COMPLETED", total_findings: 1 };
  const finding = { config_file: "main.tf", severity: "HIGH", misconfig_id: "AVD-1" };
  const api = { get: async url => { calls.push(url); return { data: { scans: { iac: scan }, findings: { iac: [finding] } } }; } };
  const response = await executionResultsApi(api, 8, 17).get("/iac/8");
  assert.deepEqual(calls, ["/reports/projects/8/executions/17"]);
  assert.deepEqual(response.data.findings, [finding]);
  assert.equal(response.data.latestScan.id, 3);
  assert.equal(executionResultsApi(api, 8, null), api);
});

test("completed empty IaC scans remain distinct from missing scans", () => {
  assert.equal(executionScanData({ scans: { iac: { status: "COMPLETED" } } }, "iac").latestScan.status, "COMPLETED");
  assert.equal(executionScanData({}, "iac").latestScan, null);
});
