"use strict";
// Clean Express fixture for CloudSentinel: no known vulnerabilities, read-only, no user input reflected.
const express = require("express");

const ITEMS = Object.freeze([
  { id: 1, name: "alpha" },
  { id: 2, name: "beta" },
  { id: 3, name: "gamma" },
]);

const app = express();
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
  });
  next();
});

app.get("/", (req, res) => res.json({ status: "ok", service: "node-clean" }));
app.get("/health", (req, res) => res.json({ status: "healthy" }));

// The only input: an optional integer limit, parsed and clamped. It is never echoed back.
app.get("/api/items", (req, res) => {
  const parsed = Number.parseInt(String(req.query.limit ?? ITEMS.length), 10);
  const limit = Number.isInteger(parsed) ? Math.min(Math.max(parsed, 0), ITEMS.length) : ITEMS.length;
  res.json({ items: ITEMS.slice(0, limit) });
});

app.use((req, res) => res.status(404).json({ error: "not found" }));
// Generic error response; details stay in the server log.
app.use((err, req, res, next) => {
  console.error("request failed:", err && err.message);
  res.status(500).json({ error: "internal error" });
});

const port = Number.parseInt(process.env.PORT || "3000", 10);
const server = app.listen(port, "0.0.0.0", () => console.log(`node-clean listening on ${port}`));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
