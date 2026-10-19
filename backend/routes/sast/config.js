"use strict";

const axios = require("axios");

const severityOrder = { CRITICAL: 1, MAJOR: 2, HIGH: 2, MINOR: 3, LOW: 3, INFO: 4 };

function sonarBaseUrl() {
  const raw = process.env.SONAR_HOST || process.env.SONAR_URL || "http://localhost:9000";
  return raw.replace(/\/$/, "");
}

function sonarOrganizationArgs(host = sonarBaseUrl()) {
  const organization = (process.env.SONAR_ORGANIZATION || "").trim();
  let hostname = "";
  try { hostname = new URL(host).hostname.toLowerCase(); } catch { /* reachability handles malformed hosts */ }
  if (["sonarcloud.io", "sonarqube.us"].includes(hostname) && !organization) {
    throw new Error("SonarQube Cloud requires SONAR_ORGANIZATION in backend/.env (use the organization key, not its display name). Restart the backend after updating it.");
  }
  return organization ? [`-Dsonar.organization=${organization}`] : [];
}

function parseEnvTimeoutMs(raw, fallback) {
  const n = Number.parseInt(String(raw ?? "").trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const GIT_CLONE_TIMEOUT_MS = parseEnvTimeoutMs(process.env.SAST_GIT_TIMEOUT_MS, 900_000);
const MAVEN_TIMEOUT_MS = parseEnvTimeoutMs(process.env.SAST_MAVEN_TIMEOUT_MS, 1_800_000);
const GRADLE_TIMEOUT_MS = parseEnvTimeoutMs(process.env.SAST_GRADLE_TIMEOUT_MS, MAVEN_TIMEOUT_MS);
const SONAR_SCANNER_TIMEOUT_MS = parseEnvTimeoutMs(process.env.SAST_SONAR_SCAN_TIMEOUT_MS, 2_700_000);
const SONAR_HTTP_TIMEOUT_MS = parseEnvTimeoutMs(process.env.SAST_SONAR_HTTP_TIMEOUT_MS, 90_000);
const SONAR_INDEX_MAX_WAIT_MS = parseEnvTimeoutMs(process.env.SAST_SONAR_INDEX_MAX_WAIT_MS, 300_000);
const SONAR_INDEX_POLL_MS = parseEnvTimeoutMs(process.env.SAST_SONAR_INDEX_POLL_MS, 5_000);

/** When true (default), Maven/Gradle errors are logged and Sonar still runs (source-only / partial Java rules). */
function continueOnBuildFailure() {
  return !/^false$/i.test(String(process.env.SAST_CONTINUE_ON_BUILD_FAILURE ?? "true").trim());
}

/** When true (default), Sonar reporting 0 ncloc/files after wait still completes with issues API results. */
function allowEmptySonarIndex() {
  return !/^false$/i.test(String(process.env.SAST_ALLOW_EMPTY_SONAR_INDEX ?? "true").trim());
}

function parseSastProjectId(raw) {
  const id = Number.parseInt(String(raw ?? "").trim(), 10);
  if (!Number.isInteger(id) || id < 1) return null;
  return id;
}

function sanitizeScanError(err) {
  if (err == null) return "SAST scan failed";
  let m = typeof err.message === "string" && err.message.trim() ? err.message.trim() : String(err);
  if (Number.isInteger(err.response?.status)) {
    const messages = Array.isArray(err.response.data?.errors)
      ? err.response.data.errors.map(e => typeof e?.msg === "string" ? e.msg : "").filter(Boolean).join("; ")
      : "";
    let endpoint = "";
    try { if (typeof err.config?.url === "string") endpoint = new URL(err.config.url, sonarBaseUrl()).pathname; } catch { /* omit malformed URL */ }
    m = `Sonar HTTP ${err.response.status}${endpoint ? ` (${endpoint})` : ""}: ${messages || m}`;
  }
  return m.length > 4000 ? `${m.slice(0, 3997)}...` : m;
}

function isGradleProjectLayout(cloneTarget) {
  const fs = require("fs");
  const path = require("path");
  if (fs.existsSync(path.join(cloneTarget, "pom.xml"))) return false;
  const hasGradleFile =
    fs.existsSync(path.join(cloneTarget, "build.gradle")) ||
    fs.existsSync(path.join(cloneTarget, "build.gradle.kts")) ||
    fs.existsSync(path.join(cloneTarget, "settings.gradle")) ||
    fs.existsSync(path.join(cloneTarget, "settings.gradle.kts"));
  const hasWrapper =
    fs.existsSync(path.join(cloneTarget, "gradlew")) || fs.existsSync(path.join(cloneTarget, "gradlew.bat"));
  return Boolean(hasGradleFile && hasWrapper);
}

function coerceIssueRow(issue, projectId) {
  const lineRaw = issue.line;
  let lineNum = null;
  if (lineRaw != null && Number.isFinite(Number(lineRaw))) lineNum = Math.trunc(Number(lineRaw));

  const rule = issue.rule != null ? String(issue.rule).slice(0, 512) : "unknown";
  const severity = issue.severity != null ? String(issue.severity).slice(0, 64) : "INFO";
  const message = issue.message != null ? String(issue.message).slice(0, 8000) : "";

  let filePath = issue.component;
  if (filePath != null && typeof filePath !== "string") {
    filePath =
      filePath.path != null
        ? String(filePath.path)
        : JSON.stringify(filePath).slice(0, 2000);
  } else if (filePath != null) {
    filePath = String(filePath).slice(0, 2000);
  }

  return [projectId, rule, severity, message, filePath, lineNum];
}

function sonarAuthAxiosConfig(extra = {}) {
  return {
    timeout: SONAR_HTTP_TIMEOUT_MS,
    auth: {
      username: process.env.SONAR_TOKEN || "",
      password: "",
    },
    ...extra,
  };
}

/**
 * GET /api/system/status before clone/build so misconfigured SONAR_HOST fails fast with a clear message
 * instead of a long Java ConnectException from sonar-scanner.
 */
async function assertSonarReachable() {
  const base = sonarBaseUrl();
  sonarOrganizationArgs(base);
  const url = `${base}/api/system/status`;
  const token = (process.env.SONAR_TOKEN || "").trim();
  const req = token
    ? sonarAuthAxiosConfig({ validateStatus: (s) => s < 500 })
    : { timeout: SONAR_HTTP_TIMEOUT_MS, validateStatus: (s) => s < 500 };

  try {
    await axios.get(url, req);
  } catch (e) {
    const code = e?.code != null ? String(e.code) : "";
    const syscall = e?.syscall != null ? String(e.syscall) : "";
    const msg = typeof e.message === "string" ? e.message : "";
    const isAxios = axios.isAxiosError(e);
    const noResponse = isAxios && !e.response;
    const looksNet =
      noResponse &&
      (code === "ECONNREFUSED" ||
        code === "ENOTFOUND" ||
        code === "ETIMEDOUT" ||
        code === "EAI_AGAIN" ||
        code === "EHOSTUNREACH" ||
        code === "ENETUNREACH" ||
        /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|connect|network|getaddrinfo|certificate/i.test(msg));
    if (looksNet) {
      throw new Error(
        `Cannot reach SonarQube/SonarCloud at ${base} (${code || syscall || msg || "network error"}). ` +
          `Start Sonar (e.g. Docker: docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community) ` +
          `and set SONAR_HOST in backend .env to that URL (same machine: http://localhost:9000; ` +
          `backend on Windows and Sonar on another host/VM: http://<that_host_LAN_IP>:9000). ` +
          `Confirm the URL opens in a browser from this machine and port 9000 is allowed by the firewall.`
      );
    }
    throw e;
  }
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const shouldKeepClone = () => /^true$/i.test((process.env.SAST_KEEP_CLONE || "").trim());
const shouldUseSonarBranchAnalysis = () =>
  /^true$/i.test((process.env.SONAR_ENABLE_BRANCH_ANALYSIS || "").trim());

module.exports = {
  severityOrder,
  sonarBaseUrl,
  sonarOrganizationArgs,
  assertSonarReachable,
  parseEnvTimeoutMs,
  GIT_CLONE_TIMEOUT_MS,
  MAVEN_TIMEOUT_MS,
  GRADLE_TIMEOUT_MS,
  SONAR_SCANNER_TIMEOUT_MS,
  SONAR_HTTP_TIMEOUT_MS,
  SONAR_INDEX_MAX_WAIT_MS,
  SONAR_INDEX_POLL_MS,
  continueOnBuildFailure,
  allowEmptySonarIndex,
  parseSastProjectId,
  sanitizeScanError,
  isGradleProjectLayout,
  coerceIssueRow,
  sonarAuthAxiosConfig,
  wait,
  shouldKeepClone,
  shouldUseSonarBranchAnalysis,
};
