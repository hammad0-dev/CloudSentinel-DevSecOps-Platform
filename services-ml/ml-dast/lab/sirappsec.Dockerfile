# SirAppSec vuln-node.js-express.js-app @ b977c74: the v3 FINAL HELD-OUT app. LAB ONLY, 127.0.0.1 only.
# Never used for training or tuning; collected and scored once by scripts/eval_final_v3.py.
# Same two stages as the upstream Dockerfile; the runtime differs only in:
#   * --unhandled-rejections=warn: several handlers throw inside promise callbacks (e.g. /beer,
#     validate-otp with an unknown id); on Node 18 that would kill the process mid-scan, so the
#     request hangs until the client timeout instead;
#   * the db/ directory the SQLite storage path expects is created;
#   * logs go to stdout (the upstream start script writes app.log);
#   * `npm install --omit=dev` instead of `npm ci`: the upstream lock file is out of sync with
#     package.json (devDependency nodemon), so `npm ci` refuses; production dependencies still
#     follow the lock file.
FROM node:18-bullseye AS builder
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .

FROM node:18-bullseye-slim
ENV NODE_ENV=development
WORKDIR /home/node/src
COPY --from=builder --chown=node:node /build ./
RUN mkdir -p /home/node/src/db /home/node/src/uploads && chown -R node:node /home/node/src/db /home/node/src/uploads
USER node
EXPOSE 5000
CMD ["node", "--unhandled-rejections=warn", "src/server.js"]
