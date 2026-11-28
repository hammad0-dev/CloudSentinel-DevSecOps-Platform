"use strict";
// Applies migration 026 (pipeline_executions source_branch, source_commit, source_commit_message for the execution report).
// Idempotent (ADD COLUMN IF NOT EXISTS, guarded constraints). Usage: cd backend && npm run migrate:source
const path = require("path");
require("dotenv").config({ path: process.env.BACKEND_ENV_FILE || path.join(__dirname, "../.env") });
const fs = require("fs");
const pool = require("../db");

(async () => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(fs.readFileSync(path.join(__dirname, "../migrations/026_execution_source.sql"), "utf8"));
    await client.query("COMMIT");
    console.log("Execution source migration 026 applied: webhook runs now record branch, commit and message.");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
})().catch((error) => {
  console.error("Execution source migration failed:", error.message);
  process.exitCode = 1;
});
