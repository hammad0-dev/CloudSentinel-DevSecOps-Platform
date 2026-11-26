"use strict";
// Trivy vulnerability DB for the container image scan (Deploy stage).
//
// Without this, `trivy image` refreshes its DB in the middle of a pipeline run whenever the cached DB has passed
// its NextUpdate time (the e2e run on 2026-11-26 measured +60 s on the first scan of the day). The warmer
// downloads the DB in the background (at backend start and every TRIVY_DB_WARM_INTERVAL_HOURS), and the image
// scan passes --skip-db-update only while the cached DB is younger than TRIVY_DB_MAX_AGE_HOURS. A missing,
// unreadable or older DB is never skipped: Trivy then updates it during the scan exactly as before, so a
// failing warmer can make a scan slower but never makes it use a stale DB.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const DEFAULT_MAX_AGE_HOURS = 48;
const DEFAULT_WARM_INTERVAL_HOURS = 6;

function trivyCmd(env = process.env) { return env.TRIVY_CMD || "trivy"; }

// Cache dir Trivy uses for the image scan. IMAGE_TRIVY_CACHE_DIR wins; otherwise Trivy's own default
// (snap Trivy keeps it under ~/snap/trivy/current/.cache, other installs under $XDG_CACHE_HOME or ~/.cache).
function cacheDir(env = process.env) {
  if (env.IMAGE_TRIVY_CACHE_DIR) return path.resolve(env.IMAGE_TRIVY_CACHE_DIR);
  if (trivyCmd(env).startsWith("/snap/")) return path.join(os.homedir(), "snap/trivy/current/.cache/trivy");
  return path.join(env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "trivy");
}

function hours(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

// { fresh, reason, downloadedAt, ageHours } from <cache>/db/metadata.json. Fresh only with a parseable
// DownloadedAt that is in the past and younger than the limit.
function dbStatus(env = process.env, now = Date.now()) {
  const maxAge = hours(env.TRIVY_DB_MAX_AGE_HOURS, DEFAULT_MAX_AGE_HOURS);
  const file = path.join(cacheDir(env), "db", "metadata.json");
  let meta;
  try { meta = JSON.parse(fs.readFileSync(file, "utf8")); } catch { return { fresh: false, reason: "no readable DB metadata" }; }
  if (!fs.existsSync(path.join(cacheDir(env), "db", "trivy.db"))) return { fresh: false, reason: "no DB file" };
  const downloaded = Date.parse(meta?.DownloadedAt);
  if (!Number.isFinite(downloaded) || downloaded > now + 5 * 60 * 1000) return { fresh: false, reason: "invalid DownloadedAt" };
  const ageHours = (now - downloaded) / 3600000;
  if (maxAge === 0 || ageHours >= maxAge) return { fresh: false, reason: `DB is ${ageHours.toFixed(1)} h old (limit ${maxAge} h)`, downloadedAt: meta.DownloadedAt, ageHours };
  return { fresh: true, reason: "fresh", downloadedAt: meta.DownloadedAt, ageHours };
}

// Extra arguments for `trivy image`.
function imageScanArgs(env = process.env, now = Date.now()) {
  const args = env.IMAGE_TRIVY_CACHE_DIR ? ["--cache-dir", cacheDir(env)] : [];
  if (dbStatus(env, now).fresh) args.push("--skip-db-update");
  return args;
}

function run(cmd, args, timeoutMs) {
  return new Promise(resolve => {
    const started = Date.now();
    const child = spawn(cmd, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.stderr.on("data", d => { stderr = (stderr + d).slice(-2000); });
    child.on("error", e => { clearTimeout(timer); resolve({ code: -1, error: e.message, ms: Date.now() - started }); });
    child.on("close", code => { clearTimeout(timer); resolve({ code, stderr, ms: Date.now() - started }); });
  });
}

// One warm-up: `trivy image --download-db-only` (Trivy itself skips the download while the DB is current).
async function warm({ env = process.env, runner = run, log = () => {} } = {}) {
  const args = ["image", "--download-db-only", "--quiet", ...(env.IMAGE_TRIVY_CACHE_DIR ? ["--cache-dir", cacheDir(env)] : [])];
  const r = await runner(trivyCmd(env), args, 10 * 60 * 1000);
  const status = dbStatus(env);
  log({ level: r.code === 0 ? "info" : "warn", event: "trivy_db_warm", detail: { code: r.code, ms: r.ms, fresh: status.fresh, downloadedAt: status.downloadedAt || null, error: r.code === 0 ? null : String(r.error || r.stderr || "").slice(-200) } });
  return { ...r, status };
}

let timer = null;
let running = null;
// Starts the background warmer unless TRIVY_DB_WARM is off. Returns a stop function.
function startWarmer({ env = process.env, runner = run, log = () => {} } = {}) {
  if (/^(0|off|false|no|disabled)$/i.test(String(env.TRIVY_DB_WARM || "").trim())) return () => {};
  const everyMs = hours(env.TRIVY_DB_WARM_INTERVAL_HOURS, DEFAULT_WARM_INTERVAL_HOURS) * 3600000;
  const tick = () => { if (!running) running = warm({ env, runner, log }).catch(() => {}).finally(() => { running = null; }); return running; };
  tick();
  if (everyMs > 0) { timer = setInterval(tick, everyMs); timer.unref?.(); }
  return () => { if (timer) clearInterval(timer); timer = null; };
}

module.exports = { cacheDir, dbStatus, imageScanArgs, warm, startWarmer, DEFAULT_MAX_AGE_HOURS, DEFAULT_WARM_INTERVAL_HOURS };
