const crypto = require("crypto");

function positiveInteger(value, label) {
  if (!Number.isInteger(value) || value <= 0) throw new Error(`A valid trusted ${label} is required for image identity`);
  return value;
}

function createImageIdentity(projectId, options = {}) {
  positiveInteger(projectId, "project ID");
  const attempt = positiveInteger(options.attempt ?? 1, "deployment attempt");
  const now = options.now ?? Date.now();
  if (!Number.isSafeInteger(now) || now <= 0) throw new Error("A valid deployment timestamp is required for image identity");
  const nonce = (options.nonce || crypto.randomBytes(6).toString("hex")).toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(nonce)) throw new Error("A valid deployment nonce is required for image identity");

  let runIdentity = "manual";
  if (options.executionId !== undefined && options.executionId !== null) {
    runIdentity = `run-${positiveInteger(options.executionId, "pipeline execution ID")}`;
  }
  const repository = `cloudsentinel-p${projectId}`;
  const tag = `${runIdentity}-attempt-${attempt}-${now.toString(36)}-${nonce}`;
  if (tag.length > 128 || !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag)) throw new Error("Generated Docker image tag is invalid");
  return { repository, tag, imageReference: `${repository}:${tag}`, executionId: options.executionId ?? null, attempt };
}

module.exports = { createImageIdentity };
