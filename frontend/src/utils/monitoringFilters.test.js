import test from "node:test";
import assert from "node:assert/strict";
import { alertMatches, alertParams, logParams, logSources } from "./monitoringFilters.js";

const a = { severity: "HIGH", status: "OPEN", project_id: 29 };
test("project selector filters alerts (list and live stream)", () => {
  assert.equal(alertMatches(a, { project: "29" }), true);
  assert.equal(alertMatches(a, { project: "24" }), false);
  assert.equal(alertMatches({ ...a, project_id: null }, { project: "29" }), false);
  assert.equal(alertMatches(a, { project: "", status: "OPEN,ACKNOWLEDGED", severity: "HIGH" }), true);
  assert.deepEqual(alertParams({ project: "29", status: "OPEN" }), { severity: undefined, status: "OPEN", projectId: "29", limit: 200 });
  assert.equal(alertParams({}).projectId, undefined);
});
test("log search sends the project and never kyverno for a project", () => {
  assert.deepEqual(logSources("29"), ["backend", "k8s"]);
  assert.deepEqual(logParams({ project: "29", source: "k8s", q: "deploy", from: 1, to: 2 }), { source: "k8s", q: "deploy", projectId: "29", from: 1, to: 2, limit: 300 });
  assert.equal(logParams({ project: "29", source: "kyverno" }).source, undefined);
  assert.equal(logParams({ source: "kyverno" }).source, "kyverno");
});
