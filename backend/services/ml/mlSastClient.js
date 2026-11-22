"use strict";
// Client for the ml-sast service (services-ml/ml-sast). Env: ML_SAST_URL, ML_SAST_TIMEOUT_MS.
// Default timeout 1,800 s: ml-sast v3 runs CodeBERT on CPU (about 0.14-0.26 s per function), so the old
// 300 s default was reached at about 1,100-2,100 functions. 1,800 s matches the orchestrator's stage timeout.
const DEFAULT_TIMEOUT_MS = 1800000;
const { createHttp, baseUrl, positiveInt, parseModelInfo, badResponse, cweNumber, confidence } = require("./mlHttp");

const SERVICE = "ml-sast";
const LABEL = "ML SAST service";
const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

function parseFindings(data, url, submittedPaths) {
  const bad = (m) => badResponse(SERVICE, LABEL, url, m);
  if (!Array.isArray(data.findings)) throw bad("findings must be an array");
  return data.findings.map((f, i) => {
    const at = `findings[${i}]`;
    if (!f || typeof f !== "object") throw bad(`${at} is not an object`);
    const rule = typeof f.rule === "string" ? f.rule.trim() : "";
    const severity = String(f.severity || "").toUpperCase();
    const message = typeof f.message === "string" ? f.message.trim() : "";
    const filePath = typeof f.file_path === "string" ? f.file_path : "";
    const line = f.line_number === null || f.line_number === undefined ? null : Number(f.line_number);
    const cwe = cweNumber(f.cwe_id);
    const conf = confidence(f.confidence);
    if (!rule || rule.length > 200) throw bad(`${at}.rule is missing or too long`);
    if (!SEVERITIES.has(severity)) throw bad(`${at}.severity "${f.severity}" is not CRITICAL|HIGH|MEDIUM|LOW|INFO`);
    if (!message) throw bad(`${at}.message is missing`);
    if (!submittedPaths.has(filePath)) throw bad(`${at}.file_path "${filePath.slice(0, 200)}" was not submitted`);
    if (line !== null && !(Number.isInteger(line) && line > 0)) throw bad(`${at}.line_number must be a positive integer`);
    if (Number.isNaN(cwe)) throw bad(`${at}.cwe_id is not a CWE number`);
    if (Number.isNaN(conf)) throw bad(`${at}.confidence must be a number in 0..1`);
    return { rule, cwe_id: cwe, severity, message, file_path: filePath, line_number: line, confidence: conf };
  });
}

function createMlSastClient({ url = process.env.ML_SAST_URL, timeoutMs = positiveInt(process.env.ML_SAST_TIMEOUT_MS, DEFAULT_TIMEOUT_MS), http } = {}) {
  const origin = baseUrl(url, "ML_SAST_URL", SERVICE);
  const client = createHttp({ url: origin, timeoutMs, service: SERVICE, label: LABEL, http });
  return {
    url: origin,
    timeoutMs,
    health: () => client.get("/health"),
    modelInfo: async () => parseModelInfo(await client.get("/model-info"), { service: SERVICE, label: LABEL, url: origin }),
    scan: async (files) => {
      const data = await client.post("/scan", { files });
      return parseFindings(data, origin, new Set(files.map((f) => f.path)));
    },
  };
}

module.exports = { createMlSastClient, parseFindings, SEVERITIES, DEFAULT_TIMEOUT_MS };
