// Intentionally vulnerable test fixture for CloudSentinel. Never deploy outside isolated staging.
const express = require("express");
const mysql = require("mysql");
const _ = require("lodash");

// VULN 1: hardcoded secrets (fake values, for scanner detection only).
const DB_PASSWORD = "Sup3rS3cretFixturePassw0rd!";
const API_TOKEN = "ghp_cloudsentinelFixtureFakeToken0000000000";

const db = mysql.createConnection({ host: "127.0.0.1", user: "app", password: DB_PASSWORD, database: "shop" });
const app = express();

app.get("/", (req, res) => res.json({ status: "ok" }));
app.get("/health", (req, res) => res.json({ status: "healthy" }));

// VULN 2: SQL built by string concatenation from user input.
app.get("/users", (req, res) => {
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(query, (err, rows) => {
    if (err) return res.status(500).json({ error: "database unavailable" });
    res.json(rows);
  });
});

// VULN 3: reflected XSS, user input written to HTML unescaped.
app.get("/search", (req, res) => {
  res.send("<html><body><h1>Results for " + req.query.q + "</h1></body></html>");
});

// Uses the outdated lodash (prototype pollution via merge).
app.get("/merge", (req, res) => res.json(_.merge({}, req.query, { token: API_TOKEN.slice(0, 4) })));

const port = Number(process.env.PORT) || 3000;
app.listen(port, "0.0.0.0", () => console.log(`fixture listening on ${port}`));
