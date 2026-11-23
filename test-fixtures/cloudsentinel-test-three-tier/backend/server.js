'use strict';
// Private API: DB_HOST/DB_PORT/DB_NAME from the ConfigMap, DB_USER/DB_PASSWORD from the RDS-managed secret.
const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false },
});
const app = express();

app.get('/', (_req, res) => res.json({ status: 'ok' }));
app.get('/items', async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT 'first' AS name UNION ALL SELECT 'second'");
    res.json(rows);
  } catch {
    res.status(500).json({ error: 'database unavailable' });
  }
});

app.listen(process.env.PORT || 3001, () => console.log('backend listening'));
