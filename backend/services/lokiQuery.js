// Module 11 FE-5: safe LogQL builder + bounded Loki query_range proxy.
const axios = require("axios");

const SOURCES = ["backend", "k8s", "kyverno"];
const LABELS = { namespace: /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/, pod: /^[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?$/, container: /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/ };
// Free text is a literal line filter: no quotes, backslashes, backticks, pipes or braces.
const SAFE_TEXT = /^[A-Za-z0-9 _.,:;@/=+#()[\]-]{1,200}$/;
const MAX_RANGE_MS = 24 * 60 * 60 * 1000;
const DEFAULT_RANGE_MS = 60 * 60 * 1000;
const MAX_LIMIT = 1000;

class LogQueryError extends Error {
  constructor(message) { super(message); this.status = 400; }
}

function quote(value) {
  return '"' + String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

function parseTime(value, name) {
  if (value === undefined || value === null || value === "") return null;
  const raw = String(value);
  const t = /^\d{13}$/.test(raw) ? Number(raw) : /^\d{10}$/.test(raw) ? Number(raw) * 1000 : Date.parse(raw);
  if (!Number.isFinite(t)) throw new LogQueryError(`Invalid ${name}`);
  return t;
}

function intList(values) {
  const ids = (values || []).map(Number);
  if (ids.some((n) => !Number.isInteger(n) || n <= 0)) throw new LogQueryError("Invalid project scope");
  return ids;
}

/**
 * @param {object} p
 * @param {string} [p.source]      backend | k8s | kyverno (omitted = all three)
 * @param {string} [p.q]           literal text, matched case-insensitively
 * @param {number[]} [p.projectIds] restrict to these projects (null = unrestricted)
 * @param {object} [p.labels]      extra stream labels: namespace, pod, container
 */
function buildLogQL({ source, q, projectIds = null, labels = {} } = {}) {
  if (source !== undefined && source !== null && source !== "" && !SOURCES.includes(source)) throw new LogQueryError("Invalid source");
  const matchers = [];
  if (source) matchers.push(`source=${quote(source)}`);
  else matchers.push(`source=~${quote(SOURCES.join("|"))}`);
  for (const [name, value] of Object.entries(labels || {})) {
    if (value === undefined || value === null || value === "") continue;
    if (!LABELS[name] || !LABELS[name].test(String(value))) throw new LogQueryError(`Invalid label ${name}`);
    matchers.push(`${name}=${quote(value)}`);
  }
  let pipeline = "";
  if (projectIds) {
    const ids = intList(projectIds);
    if (!ids.length) throw new LogQueryError("No projects in scope");
    const alt = quote(ids.join("|"));
    if (source === "backend") pipeline += ` | json projectId="projectId" | projectId=~${alt}`;
    else if (source === "k8s") matchers.push(`project_id=~${alt}`);
    else throw new LogQueryError("Project-scoped queries require source=backend or source=k8s");
  }
  if (q !== undefined && q !== null && q !== "") {
    if (typeof q !== "string" || !SAFE_TEXT.test(q)) throw new LogQueryError("Search text may only contain letters, digits, spaces and . , : ; @ / = + # ( ) [ ] - _ (max 200)");
    const escaped = q.replace(/[.*+?()[\]^$|#]/g, (c) => "\\" + c);
    pipeline = ` |~ ${quote("(?i)" + escaped)}` + pipeline;
  }
  return `{${matchers.join(", ")}}${pipeline}`;
}

function buildRange({ from, to, limit, now = Date.now() } = {}) {
  const end = parseTime(to, "to") ?? now;
  const start = parseTime(from, "from") ?? end - DEFAULT_RANGE_MS;
  if (start >= end) throw new LogQueryError("from must be before to");
  if (end - start > MAX_RANGE_MS) throw new LogQueryError("Range is limited to 24 hours");
  const n = limit === undefined || limit === "" ? 200 : Number(limit);
  if (!Number.isInteger(n) || n < 1) throw new LogQueryError("Invalid limit");
  return { start: `${start}000000`, end: `${end}000000`, limit: Math.min(n, MAX_LIMIT) };
}

function flatten(data) {
  const lines = [];
  for (const stream of data?.data?.result || []) {
    for (const [ns, line] of stream.values || []) {
      let parsed = null;
      if (line.startsWith("{")) { try { parsed = JSON.parse(line); } catch { parsed = null; } }
      lines.push({ ts: new Date(Number(BigInt(ns) / 1000000n)).toISOString(), source: stream.stream?.source || null, labels: stream.stream || {}, line, parsed });
    }
  }
  return lines.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
}

async function queryLogs(params, { http = axios, baseUrl = process.env.LOKI_URL, now } = {}) {
  if (!baseUrl) {
    const err = new Error("LOKI_URL is not configured");
    err.status = 503;
    throw err;
  }
  const query = buildLogQL(params);
  const range = buildRange({ ...params, now });
  const res = await http.get(baseUrl.replace(/\/$/, "") + "/loki/api/v1/query_range", {
    params: { query, ...range, direction: "backward" },
    timeout: 10000,
  });
  return { query, range, lines: flatten(res.data) };
}

module.exports = { buildLogQL, buildRange, queryLogs, flatten, LogQueryError, SOURCES, MAX_RANGE_MS, MAX_LIMIT };
