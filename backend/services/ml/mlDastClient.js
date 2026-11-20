"use strict";
// Client for the ml-dast service (services-ml/ml-dast). Env: ML_DAST_URL, ML_DAST_TIMEOUT_MS.
const { createHttp, baseUrl, positiveInt, parseModelInfo, badResponse, cweNumber, confidence } = require("./mlHttp");

const SERVICE = "ml-dast";
const LABEL = "ML DAST service";
// Same scale as ZAP baseline rows in dast_findings.
const SEVERITIES = new Set(["HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]);
const str = (value, max) => (value === null || value === undefined ? "" : String(value)).slice(0, max);

function parseFindings(data, url) {
  const bad = (m) => badResponse(SERVICE, LABEL, url, m);
  if (!Array.isArray(data.findings)) throw bad("findings must be an array");
  return data.findings.map((f, i) => {
    const at = `findings[${i}]`;
    if (!f || typeof f !== "object") throw bad(`${at} is not an object`);
    const severity = String(f.severity || "").toUpperCase().replace(/^INFO$/, "INFORMATIONAL");
    const alert = str(f.alert, 500).trim();
    const cwe = cweNumber(f.cwe_id);
    const conf = confidence(f.confidence);
    if (!alert) throw bad(`${at}.alert is missing`);
    if (!SEVERITIES.has(severity)) throw bad(`${at}.severity "${f.severity}" is not HIGH|MEDIUM|LOW|INFORMATIONAL`);
    if (Number.isNaN(cwe)) throw bad(`${at}.cwe_id is not a CWE number`);
    if (Number.isNaN(conf)) throw bad(`${at}.confidence must be a number in 0..1`);
    return {
      alert,
      attack_type: str(f.attack_type || alert, 500),
      severity,
      endpoint: str(f.endpoint, 500),
      method: str(f.method || "GET", 10).toUpperCase(),
      param: str(f.param, 200),
      request_payload: str(f.request_payload, 1000),
      response_details: str(f.response_details, 1000),
      cwe_id: cwe,
      solution: str(f.solution, 1000),
      confidence: conf,
    };
  });
}

function createMlDastClient({ url = process.env.ML_DAST_URL, timeoutMs = positiveInt(process.env.ML_DAST_TIMEOUT_MS, 1800000), http } = {}) {
  const origin = baseUrl(url, "ML_DAST_URL", SERVICE);
  const client = createHttp({ url: origin, timeoutMs, service: SERVICE, label: LABEL, http });
  return {
    url: origin,
    timeoutMs,
    health: () => client.get("/health"),
    modelInfo: async () => parseModelInfo(await client.get("/model-info"), { service: SERVICE, label: LABEL, url: origin }),
    scan: async (args) => (await scanDetailed(client, origin, args)).findings,
    // { findings, coverage }: coverage is ml-dast's crawl summary (pages, points_found, ...) or null.
    scanDetailed: (args) => scanDetailed(client, origin, args),
  };
}

// seedPaths / openapiUrl are sent only when configured, so older ml-dast builds keep working.
async function scanDetailed(client, origin, { baseUrl: target, maxPages, maxRequests, seedPaths = [], openapiUrl = null }) {
  const body = { baseUrl: target, maxPages, maxRequests };
  if (seedPaths.length) body.seedPaths = seedPaths;
  if (openapiUrl) body.openapiUrl = openapiUrl;
  const data = await client.post("/scan", body);
  const findings = parseFindings(data, origin);
  const coverage = data.coverage && typeof data.coverage === "object" && !Array.isArray(data.coverage) ? data.coverage : null;
  return { findings, coverage };
}

module.exports = { createMlDastClient, parseFindings, SEVERITIES };
