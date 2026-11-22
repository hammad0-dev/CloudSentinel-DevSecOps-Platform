"use strict";
// Engine flags. The trained ML services are the default engines: SAST -> ml-sast (ML_SAST_URL),
// DAST -> ml-dast (ML_DAST_URL). An ML stage that cannot reach its service, or gets an error from it,
// FAILS; there is no fallback to another engine.
// SAST_ENGINE=sonar and DAST_ENGINE=zap select the old SonarQube / ZAP adapters. They are LEGACY,
// BENCHMARK ONLY: explicit opt-in, never chosen automatically, and not needed to run the pipeline.
const { MlServiceError } = require("./mlHttp");

const DEFAULT_SAST_ENGINE = "ml";
const DEFAULT_DAST_ENGINE = "ml";
const LEGACY_ENGINES = Object.freeze({ sonar: "SonarQube (legacy, benchmark only)", zap: "OWASP ZAP (legacy, benchmark only)" });

function flag(name, allowed, fallback) {
  const raw = String(process.env[name] ?? "").trim().toLowerCase();
  if (!raw) return fallback;
  if (!allowed.includes(raw)) {
    const options = allowed.map((e) => (LEGACY_ENGINES[e] ? `${e} (legacy, benchmark only)` : e)).join(" or ");
    throw new MlServiceError(`${name}=${raw} is not supported; use ${options}.`, { code: "ENGINE_FLAG_INVALID", status: 500 });
  }
  return raw;
}

const sastEngine = () => flag("SAST_ENGINE", ["ml", "sonar"], DEFAULT_SAST_ENGINE);
const dastEngine = () => flag("DAST_ENGINE", ["ml", "zap"], DEFAULT_DAST_ENGINE);
const isLegacyEngine = (engine) => Object.prototype.hasOwnProperty.call(LEGACY_ENGINES, engine);

// An untrained service returns no findings by design; completing a gate-bearing scan on that
// would pass every project, so it is refused unless explicitly allowed (plumbing tests only).
function requireUsableModel(info, label) {
  if (info.status === "trained") return info;
  if (process.env.ML_ALLOW_UNTRAINED === "true") return info;
  throw new MlServiceError(`${label} model is untrained (${info.name} ${info.version}); refusing to report a clean scan. Train and mount a model, or set ML_ALLOW_UNTRAINED=true for plumbing tests.`, { code: "ML_MODEL_UNTRAINED", service: info.name, status: 503 });
}

// Provenance record stored on the scan row: tool = model name + version + SHA-256 of the model file.
function toolProvenance(info, extra = {}) {
  return {
    engine: "ml",
    tool: `${info.name} ${info.version} sha256:${info.sha256 || "untrained"}`,
    model: { name: info.name, version: info.version, sha256: info.sha256, status: info.status, trainedOn: info.trainedOn, metrics: info.metrics },
    ...extra,
  };
}

// Static-HTML provenance-bound executions attest Sonar/ZAP-specific evidence (quality gate, pinned
// ZAP image). ML engines do not produce it, so those executions fail closed instead of attesting.
// Only the legacy adapters can serve them (explicit SAST_ENGINE=sonar / DAST_ENGINE=zap).
function rejectProvenanceBound(binding, label) {
  if (!binding) return;
  const legacy = label.includes("DAST") ? "DAST_ENGINE=zap" : "SAST_ENGINE=sonar";
  throw new MlServiceError(`${label} is not supported for provenance-bound STATIC_HTML executions; those need the legacy ${legacy} adapter (benchmark only).`, { code: "ML_ENGINE_PROVENANCE_UNSUPPORTED", status: 409 });
}

function missingColumn(error) {
  if (error?.code !== "42703") return error;
  return new MlServiceError("ML engine provenance columns are missing; apply backend/migrations/023_scan_engine_provenance.sql.", { code: "ML_MIGRATION_MISSING", status: 500, cause: error });
}

module.exports = { sastEngine, dastEngine, isLegacyEngine, DEFAULT_SAST_ENGINE, DEFAULT_DAST_ENGINE, LEGACY_ENGINES, requireUsableModel, toolProvenance, rejectProvenanceBound, missingColumn };
