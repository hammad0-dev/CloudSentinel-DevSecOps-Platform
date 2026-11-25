'use strict';
// Serves the static UI and forwards /api/* to the private backend Service (BACKEND_URL, from the ConfigMap).
const express = require('express');
const path = require('path');
const app = express();
const backend = process.env.BACKEND_URL || 'http://localhost:3001';

app.use(express.static(path.join(__dirname, 'public')));
app.get('/api/items', async (_req, res) => {
  try {
    const r = await fetch(`${backend}/items`);
    res.status(r.status).json(await r.json());
  } catch {
    res.status(502).json({ error: 'backend unavailable' });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('frontend listening'));
