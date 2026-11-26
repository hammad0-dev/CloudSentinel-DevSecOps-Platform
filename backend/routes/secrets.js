// Module 9 / SRS FR-20: Secrets Management screen. Metadata only: secret values are never read or returned.
const router = require('express').Router();
const auth = require('../middleware/auth');
const pool = require('../db');
const secrets = require('../services/secretsInventory');

router.use(auth);
router.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

// FR-20.2: list secret metadata (name, keys count, age, namespace, source) with policy, expiry and rotation status.
router.get('/projects/:projectId', async (req, res) => {
  try { const r = await secrets.projectSecrets(pool, req.user, req.params.projectId); res.status(r.code).json(r.body); }
  catch { res.status(503).json({ error: 'Secrets inventory unavailable' }); }
});

// FR-20.4/FR-20.6: set or clear the rotation policy (days) and expiry date of one secret. Owner or admin only.
router.put('/projects/:projectId/policies', async (req, res) => {
  try { const r = await secrets.setPolicy(pool, req.user, req.params.projectId, req.body); res.status(r.code).json(r.body); }
  catch { res.status(500).json({ error: 'Secret policy could not be saved' }); }
});

module.exports = router;
