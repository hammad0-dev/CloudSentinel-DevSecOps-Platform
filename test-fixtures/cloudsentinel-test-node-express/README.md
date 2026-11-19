# CloudSentinel Node Express Test Fixture

Intentionally vulnerable Express app used by `scripts/e2e-smoke.js`. Do not deploy outside isolated staging.

Intentional issues:
- SQL injection: `/users?name=` builds SQL by string concatenation.
- Reflected XSS: `/search?q=` writes input into HTML unescaped.
- Hardcoded secrets: `DB_PASSWORD`, `API_TOKEN` in `app.js` (fake values).
- Vulnerable dependency: `lodash@4.17.15` (CVE-2020-8203, CVE-2021-23337).

No Dockerfile: CloudSentinel generates one (Node stack, port 3000). Run locally with `npm install && npm start`.
