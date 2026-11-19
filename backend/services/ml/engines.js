"use strict";
// Engine flags. SonarQube and ZAP stay the default until the ML engines pass evaluation.
const { MlServiceError } = require("./mlHttp");

function flag(name, allowed, fallback) {
  const raw = String(process.env[name] ?? "").trim().toLowerCase();
  if (!raw) return fallback;
  if (!allowed.includes(raw)) {
    throw new MlServiceError(`${name}=${raw} is not supported; use ${allowed.join(" or ")}.`, { code: "ENGINE_FLAG_INVALID", status: 500 });
  }
  return raw;
}

const sastEngine = () => flag("SAST_ENGINE", ["sonar", "ml"], "sonar");
const dastEngine = () => flag("DAST_ENGINE", ["zap", "ml"], "zap");

// An untrained service returns no findings by design; completing a gate-bearing scan on that
// would pass every project, so it is refused unless explicitly allowed (plumbing tests only).
function requireUsableModel(info, label) {
  if (info.status === "trained") return info;
  if (process.env.ML_ALLOW_UNTRAINED === "true") return info;
  throw new MlServiceError(`${label} model is untrained (${info.name} ${info.version}); refusing to report a clean scan. Train and mount a model, set ML_ALLOW_UNTRAINED=true for plumbing tests, or switch the engine flag back.`, { code: "ML_MODEL_UNTRAINED", service: info.name, status: 503 });
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
function rejectProvenanceBound(binding, label) {
  if (!binding) return;
  throw new MlServiceError(`${label} is not supported for provenance-bound STATIC_HTML executions; use the default engine.`, { code: "ML_ENGINE_PROVENANCE_UNSUPPORTED", status: 409 });
}

function missingColumn(error) {
  if (error?.code !== "42703") return error;
  return new MlServiceError("ML engine provenance columns are missing; apply backend/migrations/023_scan_engine_provenance.sql.", { code: "ML_MIGRATION_MISSING", status: 500, cause: error });
}

module.exports = { sastEngine, dastEngine, requireUsableModel, toolProvenance, rejectProvenanceBound, missingColumn };
