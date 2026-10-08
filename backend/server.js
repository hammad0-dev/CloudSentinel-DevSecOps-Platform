const path = require("path");
const express = require("express");
const cors = require("cors");
require("dotenv").config({
  path: process.env.BACKEND_ENV_FILE || path.join(__dirname, ".env"),
});
const pool = require("./db");

const app = express();

const allowedOrigins = new Set([
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:5174",
  "http://127.0.0.1:5174",
  "http://192.168.141.128:5173",
  "http://YOUR_WINDOWS_IP:5173",
]);

const isDev = process.env.NODE_ENV !== "production";

function isLocalhostHttpOrigin(origin) {
  try {
    const u = new URL(origin);
    return (
      u.protocol === "http:" &&
      (u.hostname === "localhost" || u.hostname === "127.0.0.1")
    );
  } catch {
    return false;
  }
}

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.has(origin)) return callback(null, true);
      if (isDev && isLocalhostHttpOrigin(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
  })
);
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString("utf8");
  }
}));

app.use("/api/auth", require("./routes/auth"));
app.use("/api/projects", require("./routes/projects"));
app.use("/api/sast", require("./routes/sast"));
app.use("/api/dependencies", require("./routes/dependency"));
app.use("/api/iac", require("./routes/iac"));
app.use("/api/dast", require("./routes/dast"));
app.use("/api/webhooks", require("./routes/webhooks"));
app.use("/api/deployment", require("./routes/deployment"));

const healthPayload = { ok: true, service: "CloudSentinel API" };

app.get("/", (req, res) => {
  res.json({
    message: "CloudSentinel API running",
    health: "/api/health",
  });
});

app.get("/health", (req, res) => {
  res.json(healthPayload);
});

app.get("/api/health", (req, res) => {
  res.json(healthPayload);
});

const boot = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS dependency_scans (
      id SERIAL PRIMARY KEY,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      status VARCHAR(20) DEFAULT 'RUNNING',
      target_type VARCHAR(20) DEFAULT 'fs',
      total_packages INTEGER DEFAULT 0,
      critical INTEGER DEFAULT 0,
      high INTEGER DEFAULT 0,
      medium INTEGER DEFAULT 0,
      low INTEGER DEFAULT 0,
      unknown INTEGER DEFAULT 0,
      sbom_json TEXT,
      started_at TIMESTAMP DEFAULT NOW(),
      completed_at TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sbom_components (
      id SERIAL PRIMARY KEY,
      scan_id INTEGER REFERENCES dependency_scans(id) ON DELETE CASCADE,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      pkg_name VARCHAR(200),
      pkg_version VARCHAR(100),
      pkg_type VARCHAR(50),
      license VARCHAR(100),
      cve_id VARCHAR(50),
      severity VARCHAR(20),
      cvss_score NUMERIC(4,1),
      fixed_version VARCHAR(100),
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS iac_scans (
      id SERIAL PRIMARY KEY,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      status VARCHAR(20) DEFAULT 'RUNNING',
      total_findings INTEGER DEFAULT 0,
      critical INTEGER DEFAULT 0,
      high INTEGER DEFAULT 0,
      medium INTEGER DEFAULT 0,
      low INTEGER DEFAULT 0,
      unknown INTEGER DEFAULT 0,
      started_at TIMESTAMP DEFAULT NOW(),
      completed_at TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS iac_findings (
      id SERIAL PRIMARY KEY,
      scan_id INTEGER REFERENCES iac_scans(id) ON DELETE CASCADE,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      config_file TEXT,
      misconfig_type TEXT,
      misconfig_id VARCHAR(50),
      severity VARCHAR(20),
      description TEXT,
      resolution TEXT,
      start_line INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Safe migration: add target_url and webhook columns to projects if they don't exist yet
  await pool.query(`
    ALTER TABLE projects 
      ADD COLUMN IF NOT EXISTS target_url TEXT,
      ADD COLUMN IF NOT EXISTS webhook_id VARCHAR(100),
      ADD COLUMN IF NOT EXISTS webhook_secret VARCHAR(100);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS dast_scans (
      id SERIAL PRIMARY KEY,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      target_url TEXT,
      status VARCHAR(20) DEFAULT 'RUNNING',
      total_findings INTEGER DEFAULT 0,
      high INTEGER DEFAULT 0,
      medium INTEGER DEFAULT 0,
      low INTEGER DEFAULT 0,
      informational INTEGER DEFAULT 0,
      started_at TIMESTAMP DEFAULT NOW(),
      completed_at TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS dast_findings (
      id SERIAL PRIMARY KEY,
      scan_id INTEGER REFERENCES dast_scans(id) ON DELETE CASCADE,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      alert TEXT,
      attack_type TEXT,
      severity VARCHAR(20),
      endpoint TEXT,
      method VARCHAR(10),
      param TEXT,
      request_payload TEXT,
      response_details TEXT,
      cwe_id INTEGER,
      solution TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pipeline_executions (
      id SERIAL PRIMARY KEY,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      status VARCHAR(20) DEFAULT 'IDLE',
      triggered_by VARCHAR(20),
      stages_completed TEXT,
      failure_reason TEXT,
      started_at TIMESTAMP DEFAULT NOW(),
      completed_at TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS deployment_history (
      id SERIAL PRIMARY KEY,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      status VARCHAR(20) DEFAULT 'PENDING',
      deployed_at TIMESTAMP DEFAULT NOW(),
      staging_url TEXT,
      dockerfile_source VARCHAR(20),
      manifest_source VARCHAR(20),
      app_name VARCHAR(100),
      image_tag VARCHAR(200),
      failure_reason TEXT
    );
  `);

  const orphanAfterMin = Number.parseInt(
    process.env.SAST_ORPHAN_RUN_MINUTES || "240",
    10
  );
  if (orphanAfterMin > 0) {
    try {
      const cutoff = new Date(Date.now() - orphanAfterMin * 60 * 1000).toISOString();
      const clearedSast = await pool.query(
        `UPDATE scan_history SET status = 'FAILED', completed_at = NOW()
         WHERE scan_type = 'SAST' AND status = 'RUNNING' AND started_at < $1`,
        [cutoff]
      );
      const clearedDep = await pool.query(
        `UPDATE dependency_scans SET status = 'FAILED', completed_at = NOW()
         WHERE status = 'RUNNING' AND started_at < $1`,
      [cutoff]
      );
      const clearedIac = await pool.query(
        `UPDATE iac_scans SET status = 'FAILED', completed_at = NOW()
         WHERE status = 'RUNNING' AND started_at < $1`,
        [cutoff]
      );
      const clearedDast = await pool.query(
        `UPDATE dast_scans SET status = 'FAILED', completed_at = NOW()
         WHERE status = 'RUNNING' AND started_at < $1`,
        [cutoff]
      );
      if (clearedSast.rowCount > 0 || clearedDep.rowCount > 0 || clearedIac.rowCount > 0 || clearedDast.rowCount > 0) {
        console.log(
          `[boot] Stale scans → FAILED: SAST ${clearedSast.rowCount}, dependencies ${clearedDep.rowCount}, IaC ${clearedIac.rowCount}, DAST ${clearedDast.rowCount} (> ${orphanAfterMin} min). Set SAST_ORPHAN_RUN_MINUTES=0 to disable.`
        );
      }
    } catch (e) {
      console.warn("[boot] Stale scan cleanup skipped:", e.message);
    }
  }

  const parsedPort = Number.parseInt(process.env.PORT, 10);
  const port =
    Number.isFinite(parsedPort) && parsedPort > 0 ? parsedPort : 3000;

  app.listen(port, () => {
    console.log(`CloudSentinel API listening on http://localhost:${port}`);
    console.log(`Health check: http://localhost:${port}/api/health`);
  });
};

boot().catch((error) => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
