const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const root = path.resolve(__dirname, "..");
const route = fs.readFileSync(path.join(root, "routes/sast/index.js"), "utf8");
const evidence = fs.readFileSync(path.join(root, "services/sastEvidence.js"), "utf8");
const migration = fs.readFileSync(path.join(root, "migrations/010_scan_results_scan_history_linkage.sql"), "utf8");
const orchestrator = fs.readFileSync(path.join(root, "services/orchestrator.js"), "utf8");

test("Migration 010 preserves legacy rows and enforces linked completed-scan evidence", () => {
  assert.match(migration, /FOREIGN KEY \(scan_history_id, project_id\) REFERENCES scan_history \(id, project_id\)/);
  assert.match(migration, /scan_history_completed_sast_details_linked_check/);
  assert.match(migration, /CHECK \(status <> 'COMPLETED' OR sast_details_linked = TRUE\) NOT VALID/);
  assert.doesNotMatch(migration, /UPDATE\s+scan_results/i);
});

test("SAST route delegates immutable findings to transactional persistence", () => {
  assert.match(route, /persistSastEvidence\(pool/);
  assert.doesNotMatch(route, /skipped malformed issue row/);
  assert.match(evidence, /await client\.query\("BEGIN"\)/);
  assert.match(evidence, /await client\.query\("ROLLBACK"\)/);
  assert.match(evidence, /DELETE FROM scan_results WHERE scan_history_id = \$1/);
  assert.match(evidence, /INSERT INTO scan_results \(project_id, scan_history_id,/);
  assert.match(evidence, /sast_details_linked = TRUE/);
});

test("latest completed scan policy remains isolated and preserves valid zero findings", () => {
  assert.match(route, /status = 'COMPLETED'/);
  assert.match(route, /sast_details_linked = TRUE AND sr\.scan_history_id = latest_scan\.id/);
  assert.match(route, /sast_details_linked = FALSE AND sr\.scan_history_id IS NULL/);
});

test("Module 2 SAST gate requires this execution's completed linked and consistent evidence", () => {
  assert.match(orchestrator, /sh\.pipeline_execution_id = \$2/);
  assert.match(orchestrator, /sh\.sast_details_linked = TRUE/);
  assert.match(orchestrator, /COUNT\(DISTINCT \(sr\.rule, sr\.severity, sr\.message, sr\.file_path, sr\.line_number\)\)/);
  assert.match(orchestrator, /!gate\.evidenceFound \|\| !gate\.evidenceConsistent \|\| gate\.hasCritical/);
});
