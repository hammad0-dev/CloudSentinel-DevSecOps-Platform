"use strict";
// Applies migration 023 (scan_engine + tool_provenance on scan_history and dast_scans). The default
// ML engines record their engine and model provenance there. Idempotent (ADD COLUMN IF NOT EXISTS).
// Usage: cd backend && npm run migrate:engines
const path = require("path");
require("dotenv").config({ path: process.env.BACKEND_ENV_FILE || path.join(__dirname, "../.env") });
const fs = require("fs");
const pool = require("../db");

(async () => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(fs.readFileSync(path.join(__dirname, "../migrations/023_scan_engine_provenance.sql"), "utf8"));
    await client.query("COMMIT");
    console.log("Engine provenance migration 023 applied: scan_engine and tool_provenance are available.");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
})().catch((error) => {
  console.error("Engine provenance migration failed:", error.message);
  process.exitCode = 1;
});
