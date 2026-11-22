// Display labels for the engine that produced a scan. The trained ML services are the default engines;
// SonarQube (SAST_ENGINE=sonar) and OWASP ZAP (DAST_ENGINE=zap) are legacy, benchmark-only opt-ins.
// Stored scans keep their original engine: rows without scan_engine predate the ML default.

const modelText = (name, version) => [name, version].filter(Boolean).join(" ");

/** engine: { name: "ml" | "sonar", legacy, model: { name, version, sha256 } | null } from GET /api/sast/:id */
export function sastEngineLabel(engine) {
  if (!engine) return "ML SAST";
  if (engine.name === "ml") {
    const model = modelText(engine.model?.name, engine.model?.version);
    return model ? `ML SAST · ${model}` : "ML SAST";
  }
  return "SonarQube (legacy)";
}

/** scan: a dast_scans row from GET /api/dast/:id (scan_engine, policy_name, policy_version) */
export function dastEngineLabel(scan) {
  if (!scan) return "ML DAST";
  if (scan.scan_engine === "ml") {
    const model = modelText(scan.policy_name, scan.policy_version);
    return model ? `ML DAST · ${model}` : "ML DAST";
  }
  return `${scan.policy_name || "OWASP ZAP"} (legacy)`;
}

/** Documentation link for a SAST rule: CWE page for ML rules (ml:<rule>:CWE-n), SonarSource for Sonar rules. */
export function ruleDocLink(rule) {
  const value = String(rule || "");
  if (!value) return null;
  const cwe = value.match(/CWE-(\d+)/i);
  if (value.startsWith("ml:")) {
    return cwe ? { href: `https://cwe.mitre.org/data/definitions/${cwe[1]}.html`, label: `CWE-${cwe[1]} ↗` } : null;
  }
  const rspec = value.match(/S(\d+)/);
  if (!rspec) return cwe ? { href: `https://cwe.mitre.org/data/definitions/${cwe[1]}.html`, label: `CWE-${cwe[1]} ↗` } : null;
  return { href: `https://rules.sonarsource.com/${value.split(":")[0].toLowerCase()}/RSPEC-${rspec[1]}`, label: "View SonarQube Rule Docs ↗" };
}
