"use strict";
// Applies migration 025 (secret_policies: rotation policy and expiry date per Kubernetes secret, metadata only).
// Idempotent (CREATE TABLE IF NOT EXISTS). Usage: cd backend && npm run migrate:secrets
const path = require("path");
require("dotenv").config({ path: process.env.BACKEND_ENV_FILE || path.join(__dirname, "../.env") });
const fs = require("fs");
const pool = require("../db");

(async () => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(fs.readFileSync(path.join(__dirname, "../migrations/025_secret_policies.sql"), "utf8"));
    await client.query("COMMIT");
    console.log("Secret policy migration 025 applied: secret_policies is available.");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
})().catch((error) => {
  console.error("Secret policy migration failed:", error.message);
  process.exitCode = 1;
});
