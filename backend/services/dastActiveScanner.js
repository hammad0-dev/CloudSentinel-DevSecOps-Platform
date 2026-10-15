"use strict";

// Legacy plan generator retained for offline compatibility. Production execution
// requires the Module 2 lifecycle adapter; legacy boolean assertions cannot grant it.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const { spawn } = require("child_process");
const { extractFindings, summarize, persistCompletedScan, fingerprint } = require("./dastBaselineScanner");
const { assertContainmentEvidence } = require("./dastContainment");

const POLICY = require("../config/zap-active-policy-v1.json");
const ENABLED = process.env.DAST_ACTIVE_ENABLED === "true";
const IMAGE = process.env.ZAP_IMAGE || "zaproxy/zap-stable";
const DOCKER = process.env.DOCKER_CMD || "docker";
const TIMEOUT = Number.parseInt(process.env.DAST_ACTIVE_TIMEOUT_MS || "600000", 10) || 600000;

function fail(message, status = 500, code) { const e = new Error(message); e.status = status; e.code = code; e.nonRetryable = true; return e; }
function canonical(value) { const u = new URL(String(value || "")); if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || u.hash) throw fail("Active DAST target is not an allowed HTTP(S) URL", 400); return u; }
function matchesPrefix(pathname) { return POLICY.allowedPathPrefixes.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)); }
function excluded(pathname) { return POLICY.excludedPathPatterns.some((part) => pathname.toLowerCase().includes(part)); }
function privateAddress(address) { return /^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(address) || address === "::1"; }
const PLAN_CONTEXT = "cloudsentinel-active-fixture";
const PLAN_POLICY = "cloudsentinel-active-fixture-v1";
const REPORT_PATH = "/zap/wrk/report.json";

function quoteYaml(value) { return JSON.stringify(String(value)); }
function regexEscape(value) { return String(value).replace(/[^A-Za-z0-9_]/g, m => "\\" + m); }
function assertPolicyConfiguration(policy = POLICY) {
  const approved = ["40012", "40014", "40016", "40017", "40018", "40019", "40020"];
  if (!policy || !policy.name || !policy.version || policy.maxMinutes < 1 || policy.maxActiveScanners !== 1 || policy.maxRequestsPerSecond < 1 ||
      JSON.stringify([...(policy.approvedPluginIds || [])].sort()) !== JSON.stringify(approved)) {
    throw fail("Active DAST policy configuration is invalid");
  }
  return approved;
}
function automationPlan(target, policy = POLICY) {
  const approved = assertPolicyConfiguration(policy);
  const parsed = canonical(target);
  if (!matchesPrefix(parsed.pathname) || excluded(parsed.pathname)) throw fail("Active DAST plan target is outside the approved fixture scope", 403);
  const scanUrl = parsed.toString().replace(/\/$/, "");
  const origin = parsed.origin;
  const include = "^" + regexEscape(scanUrl) + "(?:/.*)?$";
  const excludedPaths = policy.excludedPathPatterns.map((segment) =>
    "^" + regexEscape(origin) + "(?:/.*)?" + regexEscape(segment) + "(?:/|$|[?#])"
  );
  return [
    "env:",
    "  contexts:",
    "    - name: " + quoteYaml(PLAN_CONTEXT),
    "      urls: [" + quoteYaml(scanUrl) + "]",
    "      includePaths: [" + quoteYaml(include) + "]",
    "      excludePaths:",
    ...excludedPaths.map((value) => "        - " + quoteYaml(value)),
    "jobs:",
    "  - type: activeScan-policy",
    "    parameters:",
    "      name: " + quoteYaml(PLAN_POLICY),
    "    policyDefinition:",
    "      defaultStrength: Low",
    "      defaultThreshold: Off",
    "      rules:",
    ...approved.map((id) => "        - id: " + id + "\n          strength: Low\n          threshold: Low"),
    "  - type: spider",
    "    parameters:",
    "      context: " + quoteYaml(PLAN_CONTEXT),
    "      url: " + quoteYaml(scanUrl),
    "      maxDurationInMins: " + policy.maxSpiderMinutes,
    "      maxChildren: " + policy.maxChildren,
    "  - type: activeScan",
    "    parameters:",
    "      context: " + quoteYaml(PLAN_CONTEXT),
    "      url: " + quoteYaml(scanUrl),
    "      policy: " + quoteYaml(PLAN_POLICY),
    "      maxScanDurationInMins: " + policy.maxMinutes,
    "      threadPerHost: " + policy.maxActiveScanners,
    "      delayInMs: " + Math.ceil(1000 / policy.maxRequestsPerSecond),
    "  - type: report",
    "    parameters:",
    "      template: traditional-json",
    "      reportDir: /zap/wrk",
    "      reportFile: report.json",
    ""
  ].join("\n");
}
async function authorizeActiveTarget(pool, { projectId, executionId, targetUrl, lookup = dns.lookup }) {
  if (!ENABLED) throw fail("Active DAST is disabled", 403, "DAST_ACTIVE_DISABLED");
  if (!Number.isInteger(executionId) || executionId < 1) throw fail("Active DAST requires trusted pipeline execution context", 403);
  const target = canonical(targetUrl);
  if (!matchesPrefix(target.pathname) || excluded(target.pathname)) throw fail("Active DAST target path is not in the approved fixture allowlist", 403);
  const deployment = await pool.query("SELECT id, staging_url FROM deployment_history WHERE project_id=$1 AND pipeline_execution_id=$2 AND status='SUCCESS' ORDER BY id DESC LIMIT 1", [projectId, executionId]);
  if (!deployment.rows.length || canonical(deployment.rows[0].staging_url).origin !== target.origin) throw fail("Active DAST target does not match the verified deployment origin", 403);
  const allowedHost = process.env.DAST_ACTIVE_ALLOWED_HOST;
  const network = process.env.DAST_ACTIVE_DOCKER_NETWORK;
  if (!allowedHost || target.hostname !== allowedHost || !network || network === "host") throw fail("Active DAST egress containment is not configured", 403);
  if (process.env.DAST_ACTIVE_EGRESS_ENFORCED !== "true" || process.env.DAST_ACTIVE_ALLOWED_IP !== target.hostname) throw fail("Active DAST network containment is not verifiably enforced", 403);
  const resolved = await lookup(target.hostname, { all: true });
  if (!resolved.length || !resolved.every(({ address }) => privateAddress(address))) throw fail("Active DAST target resolution is outside the isolated staging network", 403);
  return { target: target.toString().replace(/\/$/, ""), deploymentId: deployment.rows[0].id, network };
}
function run(command, args, timeoutMs) { return new Promise((resolve, reject) => { const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], shell: false }); let out = "", err = "", done = false; const timer = setTimeout(() => { if (!done) { done = true; child.kill("SIGKILL"); reject(fail("Active DAST timed out")); } }, timeoutMs); child.stdout.on("data", c => out += c); child.stderr.on("data", c => err += c); child.on("error", e => { if (!done) { done=true; clearTimeout(timer); reject(fail("Active DAST runner failed")); } }); child.on("close", code => { if (done) return; done=true; clearTimeout(timer); if ([0,1,2].includes(code)) resolve({out,err}); else reject(fail("Active DAST runner failed")); }); }); }
async function runActiveScan({ pool, projectId, executionId, targetUrl, lookup, runner = run, fsImpl = fs, containmentProbe = async () => { throw fail("Active DAST containment gateway is unavailable"); } }) {
  const auth = await authorizeActiveTarget(pool, { projectId, executionId, targetUrl, lookup });
  const containment = assertContainmentEvidence(await containmentProbe({ target: auth.target, network: auth.network }), auth.target);
  if (runner === run) throw fail('Active runtime lifecycle adapter is not implemented', 403, 'ACTIVE_RUNTIME_NOT_IMPLEMENTED');
  const group = crypto.randomUUID();
  const inserted = await pool.query("INSERT INTO dast_scans (project_id,pipeline_execution_id,target_url,status,started_at,scan_mode,scan_group_id,policy_name,policy_version,target_authorization) VALUES ($1,$2,$3,'RUNNING',NOW(),'ACTIVE',$4,$5,$6,$7) RETURNING id", [projectId, executionId, auth.target, group, POLICY.name, POLICY.version, JSON.stringify({ type:"verified_staging_active_fixture", deploymentId:auth.deploymentId, target:auth.target, dockerNetwork:auth.network })]);
  const scanId = inserted.rows[0].id; let dir;
  try { dir=fsImpl.mkdtempSync(`/tmp/zap-active-${projectId}-${scanId}-`); const report=path.join(dir,"report.json"), plan=path.join(dir,"automation.yaml"); fsImpl.writeFileSync(plan,automationPlan(auth.target)); await runner(DOCKER,["run","--rm","--network",auth.network,"--read-only","--tmpfs","/tmp:rw,noexec,nosuid,size=64m","--cap-drop","ALL","--pids-limit","128","-v",String(dir)+":/zap/wrk:rw",IMAGE,"zap.sh","-cmd","-autorun","/zap/wrk/automation.yaml"],TIMEOUT); if(!fsImpl.existsSync(report)) throw fail("Active DAST report was not produced"); let parsed; try { parsed=JSON.parse(fsImpl.readFileSync(report,"utf8")); } catch (_) { throw fail("Active DAST report could not be parsed"); } const findings=extractFindings(parsed); for(const finding of findings) finding.finding_fingerprint=fingerprint({...finding,attack_type:`ACTIVE:${finding.attack_type}`}); const summary=summarize(findings); await persistCompletedScan(pool,scanId,projectId,findings,summary); return { scanId, scanGroupId:group, summary }; }
  catch(error) { await pool.query("UPDATE dast_scans SET status='FAILED',failure_reason=$1,completed_at=NOW() WHERE id=$2 AND project_id=$3 AND status='RUNNING'",[String(error.message).slice(0,2000),scanId,projectId]).catch(()=>{}); throw error; }
  finally { if(dir && fsImpl.existsSync(dir)) fsImpl.rmSync(dir,{recursive:true,force:true}); }
}
module.exports={ POLICY, authorizeActiveTarget, runActiveScan, matchesPrefix, excluded, automationPlan, assertPolicyConfiguration, PLAN_CONTEXT, PLAN_POLICY, REPORT_PATH };
