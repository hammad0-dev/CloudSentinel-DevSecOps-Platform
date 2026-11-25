# CloudSentinel Node Clean Test Fixture

A small Express app with no intended vulnerabilities, used by `scripts/e2e-smoke.js node-clean` to show a Node.js
project passing every pipeline stage (SAST, dependency, IaC, image build and scan, Minikube deploy, DAST). It is the
clean counterpart of `cloudsentinel-test-node-express`, which is intentionally vulnerable.

- Routes: `GET /` and `GET /health` (JSON), and `GET /api/items?limit=N`. `limit` is parsed as an integer and clamped,
  and it is never reflected in the response.
- Security headers on every response (`X-Content-Type-Options: nosniff`, CSP `default-src 'none'`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`); `X-Powered-By` is disabled.
- Generic 404 and 500 responses; no stack traces are sent to the client.
- `Dockerfile`: `node:22-alpine` pinned by digest, `npm ci --omit=dev`, runs as UID/GID 10001, port 3000, and writes
  nothing at runtime.
- One dependency: `express@5.3.0`, locked in `package-lock.json`.

Run locally: `npm ci && npm start`, then `curl localhost:3000/health`.
