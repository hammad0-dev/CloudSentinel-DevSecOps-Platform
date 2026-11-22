"use strict";
// Shared HTTP plumbing for the ML scan services (ml-sast, ml-dast): bounded time, clear errors.
const axios = require("axios");

class MlServiceError extends Error {
  constructor(message, { code, service, status = 502, cause } = {}) {
    super(message);
    this.name = "MlServiceError";
    this.code = code;
    this.service = service;
    this.status = status;
    this.nonRetryable = true;
    if (cause) this.cause = cause;
  }
}

function positiveInt(value, fallback) {
  const n = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

function baseUrl(raw, envName, service) {
  const value = String(raw ?? "").trim();
  if (!value) throw new MlServiceError(`${envName} is not set; ${service} cannot be reached.`, { code: "ML_URL_MISSING", service, status: 500 });
  let parsed;
  try { parsed = new URL(value); } catch { parsed = null; }
  if (!parsed || !["http:", "https:"].includes(parsed.protocol)) {
    throw new MlServiceError(`${envName} must be an http(s) URL.`, { code: "ML_URL_INVALID", service, status: 500 });
  }
  return parsed.origin + parsed.pathname.replace(/\/+$/, "");
}

function describe(error, { service, url, timeoutMs, label }) {
  const where = `${label} at ${url}`;
  if (error?.code === "ECONNABORTED" || error?.code === "ETIMEDOUT" || error?.name === "CanceledError" || error?.name === "AbortError") {
    return new MlServiceError(`${where} did not respond within ${Math.round(timeoutMs / 1000)}s.`, { code: "ML_SERVICE_TIMEOUT", service, status: 504, cause: error });
  }
  if (error?.response) {
    const detail = error.response.data?.detail;
    const text = typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : "";
    return new MlServiceError(`${where} returned HTTP ${error.response.status}${text ? `: ${text.slice(0, 300)}` : ""}.`, { code: "ML_SERVICE_HTTP_ERROR", service, status: 502, cause: error });
  }
  const code = error?.code || error?.cause?.code || "NETWORK_ERROR";
  return new MlServiceError(`${where} is unreachable (${code}). Start the service; the stage does not fall back to another engine.`, { code: "ML_SERVICE_UNREACHABLE", service, status: 502, cause: error });
}

function createHttp({ url, timeoutMs, service, label, http = axios }) {
  async function call(method, path, body) {
    try {
      const response = await http.request({
        method,
        url: url + path,
        data: body,
        timeout: timeoutMs,
        signal: AbortSignal.timeout(timeoutMs + 1000),
        maxContentLength: 50 * 1024 * 1024,
        maxBodyLength: 100 * 1024 * 1024,
        headers: { "content-type": "application/json" },
      });
      if (!response || typeof response.data !== "object" || response.data === null) {
        throw new MlServiceError(`${label} at ${url} returned a non-JSON response for ${path}.`, { code: "ML_SERVICE_BAD_RESPONSE", service });
      }
      return response.data;
    } catch (error) {
      if (error instanceof MlServiceError) throw error;
      throw describe(error, { service, url, timeoutMs, label });
    }
  }
  return { get: (path) => call("GET", path), post: (path, body) => call("POST", path, body) };
}

function badResponse(service, label, url, message) {
  return new MlServiceError(`${label} at ${url} returned an invalid response: ${message}`, { code: "ML_SERVICE_BAD_RESPONSE", service });
}

const SHA256 = /^[a-f0-9]{64}$/;

function parseModelInfo(data, { service, label, url }) {
  const bad = (m) => badResponse(service, label, url, m);
  if (typeof data.name !== "string" || !data.name.trim()) throw bad("model-info.name is missing");
  if (typeof data.version !== "string" || !data.version.trim()) throw bad("model-info.version is missing");
  const status = data.status === "trained" ? "trained" : data.status === "untrained" ? "untrained" : null;
  if (!status) throw bad("model-info.status must be trained or untrained");
  if (status === "trained" && !SHA256.test(String(data.sha256 || ""))) throw bad("a trained model must report its SHA-256");
  return {
    name: data.name.trim().slice(0, 100),
    version: data.version.trim().slice(0, 100),
    sha256: status === "trained" ? data.sha256 : null,
    trainedOn: data.trained_on ?? null,
    metrics: data.metrics && typeof data.metrics === "object" ? data.metrics : {},
    status,
  };
}

function cweNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(String(value).replace(/^CWE-/i, ""));
  return Number.isInteger(n) && n > 0 ? n : NaN;
}

function confidence(value) {
  const n = Number(value);
  return typeof value === "number" && n >= 0 && n <= 1 ? n : NaN;
}

module.exports = { MlServiceError, createHttp, baseUrl, positiveInt, parseModelInfo, badResponse, cweNumber, confidence };
