'use strict';
// SEC-4 / Module 9 FE-2: committed-secret scan of the cloned repository with Trivy's secret scanner
// (`trivy fs --scanners secret`). It runs inside the IaC stage (routes/iac.js), on the same checkout as
// `trivy config`. Every match is stored as a CRITICAL iac_findings row (misconfig_id "secret:<rule>"), so the
// existing IaC gate (iac_scans.critical > 0) stops the pipeline.
//
// Hardening: Trivy reads trivy.yaml, .trivyignore and trivy-secret.yaml from its working directory. A scanned
// repository must not be able to switch off its own secret rules, so Trivy runs from a neutral directory with an
// empty ignore file and a secret-config path that does not exist (built-in rules only).
//
// The matched value never leaves Trivy's output: Match and Code are dropped and only rule, title, file and line
// are kept. Nothing here logs Trivy's raw output.
const fs = require('fs');
const path = require('path');

const enabled = (env = process.env) => String(env.IAC_SECRET_SCAN || 'on').trim().toLowerCase() !== 'off';

function neutralDir(root) {
  const dir = fs.mkdtempSync(path.join(root, 'trivy-neutral-'));
  fs.writeFileSync(path.join(dir, 'empty.trivyignore'), '');
  return dir;
}

function args(target, neutral) {
  return ['fs', '--scanners', 'secret', '--format', 'json', '--quiet', '--exit-code', '0',
    '--ignorefile', path.join(neutral, 'empty.trivyignore'),
    '--secret-config', path.join(neutral, 'no-repo-secret-config.yaml'),
    target];
}

const clip = (s, n) => String(s ?? '').slice(0, n);

// Returns iac_findings-shaped rows. Throws on output that is not a Trivy JSON report (fail closed).
function findingsFrom(raw) {
  let data;
  try { data = JSON.parse(String(raw || '').trim()); } catch { data = null; }
  if (!data || typeof data !== 'object' || (data.Results !== undefined && !Array.isArray(data.Results))) {
    const error = new Error('Trivy secret scan returned no valid JSON report');
    error.code = 'SECRET_SCAN_UNVERIFIED';
    throw error;
  }
  const findings = [];
  for (const result of data.Results || []) {
    for (const s of result.Secrets || []) {
      const rule = clip(s.RuleID || 'unknown-rule', 200);
      findings.push({
        config_file: clip(result.Target || 'unknown', 500),
        misconfig_type: clip(`Committed secret: ${s.Title || rule}`, 200),
        misconfig_id: `secret:${rule}`,
        severity: 'CRITICAL',
        description: clip(`Trivy secret rule ${rule} (${s.Category || 'uncategorised'}; scanner severity ${String(s.Severity || 'UNKNOWN').toUpperCase()}) matched at line ${s.StartLine ?? '?'}. The matched value is not stored.`, 500),
        resolution: 'Remove the secret from the repository and its git history, rotate it at the provider, and load it at runtime from a secret store (Module 9).',
        start_line: Number.isInteger(s.StartLine) ? s.StartLine : null,
      });
    }
  }
  return findings;
}

async function scan({ run, cloneRoot, target, timeoutMs }) {
  const neutral = neutralDir(cloneRoot);
  try {
    const out = await run(args(target, neutral), neutral, timeoutMs);
    return findingsFrom(typeof out === 'object' ? out.stdout : out);
  } finally {
    fs.rmSync(neutral, { recursive: true, force: true });
  }
}

module.exports = { enabled, args, findingsFrom, scan, neutralDir };
