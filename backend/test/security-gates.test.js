// SEC-4 / Module 9 FE-2 and Module 6/8 gates: Trivy secret scan in the IaC stage, dependency and image gates that
// block HIGH with a fix as well as CRITICAL. No network, no Trivy binary, no database: everything is mocked.
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const gate = require("../services/vulnerabilityGate");
const secretScan = require("../services/secretScan");
const { scanContainerImage } = require("../services/imageVulnerabilityScan");
const { normalize } = require("../services/governance/normalize");

const withEnv = async (vars, fn) => {
  const saved = Object.fromEntries(Object.keys(vars).map(k => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
};

// ---- vulnerability gate policy ------------------------------------------------------------------------------
test("gate defaults: CRITICAL always blocks, HIGH blocks only with a fix, MEDIUM/LOW never", () => {
  const p = gate.policy("DEPENDENCY", {});
  assert.deepEqual(p.fixable, ["CRITICAL", "HIGH"]);
  assert.deepEqual(p.unfixed, ["CRITICAL"]);
  const r = gate.evaluate([
    { severity: "CRITICAL", fixed_version: null },
    { severity: "HIGH", fixed_version: "2.0.1" },
    { severity: "HIGH", fixed_version: "" },
    { severity: "MEDIUM", fixed_version: "1.2" },
    { severity: "LOW", fixedVersion: "1.3" },
  ], p);
  assert.equal(r.blocked, true);
  assert.deepEqual(r.blocking, { CRITICAL: 1, HIGH: 1 });
  assert.deepEqual(r.ignoredUnfixed, { HIGH: 1 });
  assert.equal(r.reason, "1 CRITICAL, 1 HIGH (fix available)");
});

test("gate: unfixed HIGH alone does not block; fixed HIGH alone does", () => {
  const p = gate.policy("IMAGE", {});
  assert.equal(gate.evaluate([{ severity: "HIGH", fixedVersion: null }], p).blocked, false);
  assert.equal(gate.evaluate([{ severity: "HIGH", fixedVersion: "1:1.2.13-2" }], p).blocked, true);
  assert.equal(gate.evaluate([], p).blocked, false);
});

test("gate thresholds are configurable by env; previous behaviour is *_GATE_SEVERITIES=CRITICAL", () => {
  const old = gate.policy("IMAGE", { IMAGE_GATE_SEVERITIES: "CRITICAL" });
  assert.deepEqual(old.fixable, ["CRITICAL"]);
  assert.equal(gate.evaluate([{ severity: "HIGH", fixedVersion: "1.1" }], old).blocked, false);
  assert.equal(gate.evaluate([{ severity: "CRITICAL" }], old).blocked, true);
  const strict = gate.policy("DEPENDENCY", { DEPENDENCY_GATE_SEVERITIES: "critical, high, medium", DEPENDENCY_GATE_UNFIXED_SEVERITIES: "CRITICAL,HIGH" });
  assert.deepEqual(strict.fixable, ["CRITICAL", "HIGH", "MEDIUM"]);
  assert.equal(gate.evaluate([{ severity: "HIGH" }], strict).blocked, true);
  const unfixedNone = gate.policy("DEPENDENCY", { DEPENDENCY_GATE_UNFIXED_SEVERITIES: "none" });
  assert.deepEqual(unfixedNone.unfixed, []);
  assert.equal(gate.evaluate([{ severity: "CRITICAL" }], unfixedNone).blocked, false);
  // A severity that blocks without a fix also blocks with one.
  assert.deepEqual(gate.policy("IMAGE", { IMAGE_GATE_SEVERITIES: "HIGH" }).fixable, ["CRITICAL", "HIGH"]);
});

test("invalid gate config fails closed with GATE_CONFIG_INVALID", () => {
  assert.throws(() => gate.policy("DEPENDENCY", { DEPENDENCY_GATE_SEVERITIES: "CRITICAL,SEVERE" }), e => e.code === "GATE_CONFIG_INVALID");
  assert.throws(() => gate.policy("IMAGE", { IMAGE_GATE_UNFIXED_SEVERITIES: "," }), e => e.code === "GATE_CONFIG_INVALID");
  assert.throws(() => gate.policy("NOPE", {}), /Unknown gate/);
});

test("gate description names what blocks", () => {
  assert.equal(gate.describe(gate.policy("IMAGE", {})), "blocks CRITICAL always; HIGH when a fix is available");
  assert.equal(gate.describe(gate.policy("IMAGE", { IMAGE_GATE_SEVERITIES: "none", IMAGE_GATE_UNFIXED_SEVERITIES: "none" })), "blocks nothing");
});

// ---- image gate ---------------------------------------------------------------------------------------------
function imageSetup(vulns) {
  const queries = [];
  const pool = { query: async (sql, params) => { queries.push({ sql, params }); return sql.includes("INSERT INTO image_scans") ? { rows: [{ id: 7 }] } : { rows: [] }; } };
  const output = JSON.stringify({ Results: [{ Class: "os-pkgs", Type: "debian", Vulnerabilities: vulns }] });
  return { pool, queries, execute: async () => output };
}
const imageArgs = c => ({ pool: c.pool, execute: c.execute, cwd: "/tmp/p", projectId: 4, pipelineExecutionId: 9, deploymentAttempt: 1, imageTag: "cloudsentinel-p4:run-9" });

test("image gate blocks a HIGH OS vulnerability that has a fix (non-retryable)", async () => {
  await withEnv({ IMAGE_GATE_SEVERITIES: undefined, IMAGE_GATE_UNFIXED_SEVERITIES: undefined }, async () => {
    const c = imageSetup([{ VulnerabilityID: "CVE-2099-0100", Severity: "HIGH", PkgName: "libssl3", InstalledVersion: "3.0.1", FixedVersion: "3.0.2" }]);
    await assert.rejects(scanContainerImage(imageArgs(c)), e => e.code === "IMAGE_SECURITY_GATE_BLOCKED" && e.nonRetryable === true
      && /1 HIGH \(fix available\)/.test(e.message) && e.gate.blocking.HIGH === 1);
    assert.ok(c.queries.find(q => q.sql.includes("UPDATE image_scans") && q.params?.[0] === "BLOCKED"));
  });
});

test("image gate passes HIGH vulnerabilities without a fix and records them", async () => {
  await withEnv({ IMAGE_GATE_SEVERITIES: undefined, IMAGE_GATE_UNFIXED_SEVERITIES: undefined }, async () => {
    const c = imageSetup([{ VulnerabilityID: "CVE-2099-0101", Severity: "HIGH", PkgName: "libc6", InstalledVersion: "2.36" }]);
    const r = await scanContainerImage(imageArgs(c));
    assert.equal(r.gate.blocked, false);
    assert.deepEqual(r.gate.ignoredUnfixed, { HIGH: 1 });
    assert.equal(r.summary.high, 1);
    assert.ok(c.queries.find(q => q.sql.includes("UPDATE image_scans") && q.params?.[0] === "COMPLETED"));
  });
});

test("image gate with IMAGE_GATE_SEVERITIES=CRITICAL keeps the old rule (fixed HIGH passes)", async () => {
  await withEnv({ IMAGE_GATE_SEVERITIES: "CRITICAL" }, async () => {
    const c = imageSetup([{ VulnerabilityID: "CVE-2099-0102", Severity: "HIGH", PkgName: "zlib1g", FixedVersion: "1.3" }]);
    assert.equal((await scanContainerImage(imageArgs(c))).gate.blocked, false);
  });
});

test("image gate with an invalid threshold fails closed and records the failure", async () => {
  await withEnv({ IMAGE_GATE_SEVERITIES: "HIGHEST" }, async () => {
    const c = imageSetup([]);
    await assert.rejects(scanContainerImage(imageArgs(c)), e => e.code === "GATE_CONFIG_INVALID");
    assert.ok(c.queries.find(q => q.sql.includes("UPDATE image_scans") && q.sql.includes("'FAILED'")));
  });
});

// ---- dependency gate (orchestrator) ---------------------------------------------------------------------------
const { dependencyGate } = require("../services/orchestrator");
const sbomDb = rows => ({ query: async (sql, params) => { assert.match(sql, /FROM sbom_components WHERE project_id = \$1 AND scan_id = \$2/); assert.deepEqual(params, [3, 41]); return { rows }; } });

test("dependency gate blocks a fixable HIGH from the persisted SBOM rows", async () => {
  await withEnv({ DEPENDENCY_GATE_SEVERITIES: undefined, DEPENDENCY_GATE_UNFIXED_SEVERITIES: undefined }, async () => {
    const r = await dependencyGate(3, { id: 41, critical: 0 }, sbomDb([
      { severity: "HIGH", fixed_version: "4.21.2", cve_id: "CVE-2099-1" },
      { severity: "NONE", fixed_version: null, cve_id: null },
    ]));
    assert.equal(r.hasCritical, true);
    assert.equal(r.evidenceConsistent, true);
    assert.match(r.reason, /Dependency security gate: 1 HIGH \(fix available\) vulnerability \(blocks CRITICAL always; HIGH when a fix is available\)/);
  });
});

test("dependency gate passes unfixed HIGH and flags a CRITICAL count mismatch as inconsistent evidence", async () => {
  await withEnv({ DEPENDENCY_GATE_SEVERITIES: undefined, DEPENDENCY_GATE_UNFIXED_SEVERITIES: undefined }, async () => {
    const pass = await dependencyGate(3, { id: 41, critical: 0 }, sbomDb([{ severity: "HIGH", fixed_version: null, cve_id: "CVE-2099-2" }]));
    assert.equal(pass.hasCritical, false);
    assert.equal(pass.reason, null);
    const mismatch = await dependencyGate(3, { id: 41, critical: 2 }, sbomDb([{ severity: "CRITICAL", fixed_version: "1", cve_id: "CVE-2099-3" }]));
    assert.equal(mismatch.evidenceConsistent, false);
  });
});

// ---- Trivy secret scan (IaC stage) ----------------------------------------------------------------------------
const trivySecretReport = JSON.stringify({ SchemaVersion: 2, Results: [{ Target: "app/settings.py", Class: "secret", Secrets: [
  { RuleID: "aws-access-key-id", Category: "AWS", Severity: "CRITICAL", Title: "AWS Access Key ID", StartLine: 3, EndLine: 3, Match: "AWS_ACCESS_KEY_ID = \"****\"", Code: { Lines: [{ Content: "SHOULD-NOT-BE-STORED" }] } },
  { RuleID: "github-pat", Category: "GitHub", Severity: "HIGH", Title: "GitHub Personal Access Token", StartLine: 9, Match: "token=****" },
] }] });

test("secret findings are CRITICAL iac rows with rule, file and line only (no matched value)", () => {
  const f = secretScan.findingsFrom(trivySecretReport);
  assert.equal(f.length, 2);
  assert.deepEqual(f.map(x => [x.config_file, x.misconfig_id, x.severity, x.start_line]),
    [["app/settings.py", "secret:aws-access-key-id", "CRITICAL", 3], ["app/settings.py", "secret:github-pat", "CRITICAL", 9]]);
  assert.match(f[1].description, /scanner severity HIGH/);
  const stored = JSON.stringify(f);
  assert.ok(!stored.includes("****") && !stored.includes("SHOULD-NOT-BE-STORED") && !stored.includes("token="));
});

test("an empty report gives no findings; a non-JSON report fails closed", () => {
  assert.deepEqual(secretScan.findingsFrom(JSON.stringify({ SchemaVersion: 2 })), []);
  assert.deepEqual(secretScan.findingsFrom(JSON.stringify({ Results: [{ Target: "a", Secrets: null }] })), []);
  assert.throws(() => secretScan.findingsFrom("FATAL error"), e => e.code === "SECRET_SCAN_UNVERIFIED");
  assert.throws(() => secretScan.findingsFrom(JSON.stringify({ Results: "x" })), e => e.code === "SECRET_SCAN_UNVERIFIED");
});

test("secret scan runs from a neutral directory so the repository cannot disable its own rules", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cs-secret-test-"));
  const repo = path.join(root, "repo"); fs.mkdirSync(repo);
  let seen;
  const findings = await secretScan.scan({ cloneRoot: root, target: repo, timeoutMs: 1000, run: async (args, cwd) => {
    seen = { args, cwd, ignore: fs.readFileSync(args[args.indexOf("--ignorefile") + 1], "utf8") };
    return { stdout: trivySecretReport };
  } });
  assert.equal(findings.length, 2);
  assert.deepEqual(seen.args.slice(0, 3), ["fs", "--scanners", "secret"]);
  assert.equal(seen.args.at(-1), repo);
  assert.notEqual(seen.cwd, repo);
  assert.ok(!seen.cwd.startsWith(repo + path.sep));
  assert.equal(seen.ignore, "");
  const secretConfig = seen.args[seen.args.indexOf("--secret-config") + 1];
  assert.ok(!secretConfig.startsWith(repo) && !fs.existsSync(secretConfig));
  assert.equal(fs.existsSync(seen.cwd), false, "neutral directory removed afterwards");
  fs.rmSync(root, { recursive: true, force: true });
});

test("IAC_SECRET_SCAN=off is the only way to disable the secret scan", () => {
  assert.equal(secretScan.enabled({}), true);
  assert.equal(secretScan.enabled({ IAC_SECRET_SCAN: "on" }), true);
  assert.equal(secretScan.enabled({ IAC_SECRET_SCAN: "OFF" }), false);
});

test("governance classifies committed secrets as VULNERABILITY with CWE-798", () => {
  const f = normalize("IAC", { id: 1, misconfig_id: "secret:aws-access-key-id", misconfig_type: "Committed secret: AWS Access Key ID", severity: "CRITICAL", config_file: "settings.py", start_line: 3 },
    { project_id: 3, scan_id: 5, detailTable: "iac_findings" });
  assert.equal(f.classification, "VULNERABILITY");
  assert.deepEqual(f.references, ["CWE-798"]);
  const m = normalize("IAC", { id: 2, misconfig_id: "AVD-AWS-0017", severity: "LOW", config_file: "main.tf" }, { project_id: 3, scan_id: 5, detailTable: "iac_findings" });
  assert.equal(m.classification, "MISCONFIGURATION");
});
