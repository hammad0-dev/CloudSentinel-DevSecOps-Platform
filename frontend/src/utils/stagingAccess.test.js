import test from "node:test";
import assert from "node:assert/strict";
import { portForwardCommand, stagingAccess } from "./stagingAccess.js";
test("port-forward command for the project's staging Service (execution 123: project 29, app test1)", () => {
  assert.equal(portForwardCommand(29, "test1"), "kubectl --context minikube -n cloudsentinel-p-29 port-forward service/test1 8080:80");
  const a = stagingAccess({ projectId: "29", appName: "test1", stagingUrl: "http://192.168.49.2:32559" });
  assert.equal(a.label, "reachable from the WSL host only"); assert.equal(a.localUrl, "http://localhost:8080");
  assert.equal(portForwardCommand(29, "bad name; rm -rf /"), null);
  assert.equal(portForwardCommand("x", "test1"), null);
  assert.equal(stagingAccess({ projectId: 29, appName: "", stagingUrl: null }).command, null);
});
