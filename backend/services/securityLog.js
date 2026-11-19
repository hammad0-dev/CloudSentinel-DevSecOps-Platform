// Module 11 FE-1: structured JSON event log (stdout + backend/logs/app.log), in-memory window for detection.
const fs = require("fs");
const path = require("path");
const { EventEmitter } = require("events");

const LEVELS = new Set(["debug", "info", "warn", "error"]);
const WINDOW_MS = 30 * 60 * 1000;
const MAX_BUFFER = 20000;
const bus = new EventEmitter();
const buffer = [];
let fileStream = null;
let fileDisabled = process.env.APP_LOG_FILE === "off";

function logFile() {
  return process.env.APP_LOG_FILE || path.join(__dirname, "..", "logs", "app.log");
}

function writeFile(line) {
  if (fileDisabled) return;
  try {
    if (!fileStream) {
      fs.mkdirSync(path.dirname(logFile()), { recursive: true });
      fileStream = fs.createWriteStream(logFile(), { flags: "a" });
      fileStream.on("error", () => { fileDisabled = true; });
    }
    fileStream.write(line + "\n");
  } catch {
    fileDisabled = true;
  }
}

// Optional Loki push client (FE-4): set LOKI_PUSH_URL when Promtail cannot mount backend/logs.
const pending = [];
let pushTimer = null;
function queuePush(entry, line) {
  const url = process.env.LOKI_PUSH_URL;
  if (!url) return;
  pending.push([String(Date.parse(entry.ts) * 1e6), line]);
  if (pending.length > 5000) pending.splice(0, pending.length - 5000);
  if (pushTimer) return;
  pushTimer = setTimeout(() => {
    pushTimer = null;
    const values = pending.splice(0);
    require("axios").post(url.replace(/\/$/, "") + "/loki/api/v1/push",
      { streams: [{ stream: { source: "backend", job: "cloudsentinel-backend" }, values }] },
      { timeout: 5000 }).catch(() => {});
  }, 2000);
  pushTimer.unref?.();
}

function toId(value) {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  return Number.isInteger(n) ? n : String(value);
}

function logEvent({ level = "info", source = "backend", event, projectId, userId, ip, detail } = {}, { now = Date.now() } = {}) {
  if (!event) throw new Error("event is required");
  const entry = {
    ts: new Date(now).toISOString(),
    level: LEVELS.has(level) ? level : "info",
    source,
    event,
    projectId: toId(projectId),
    userId: toId(userId),
    ip: ip || null,
    detail: detail || {},
  };
  const line = JSON.stringify(entry);
  if (process.env.APP_LOG_STDOUT !== "off") process.stdout.write(line + "\n");
  writeFile(line);
  queuePush(entry, line);
  buffer.push(entry);
  const cutoff = now - WINDOW_MS;
  while (buffer.length && (buffer.length > MAX_BUFFER || Date.parse(buffer[0].ts) < cutoff)) buffer.shift();
  bus.emit("event", entry);
  return entry;
}

function recentEvents(sinceMs = WINDOW_MS, now = Date.now()) {
  const cutoff = now - sinceMs;
  return buffer.filter((e) => Date.parse(e.ts) >= cutoff);
}

function clientIp(req) {
  return req?.ip || req?.socket?.remoteAddress || null;
}

// One line per HTTP request; path only (never query strings, which may carry secrets).
const SKIP_PATHS = new Set(["/metrics", "/api/monitoring/stream", "/health", "/api/health"]);
function requestLogger(req, res, next) {
  const started = process.hrtime.bigint();
  res.on("finish", () => {
    const urlPath = String(req.originalUrl || req.url || "").split("?")[0];
    if (SKIP_PATHS.has(urlPath)) return;
    const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
    logEvent({
      level: res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "info",
      event: "http_request",
      userId: req.user?.id,
      ip: clientIp(req),
      detail: { method: req.method, path: urlPath, status: res.statusCode, durationMs: Math.round(durationMs) },
    });
  });
  next();
}

function _reset() {
  buffer.length = 0;
}

module.exports = { logEvent, recentEvents, requestLogger, clientIp, bus, _reset };
