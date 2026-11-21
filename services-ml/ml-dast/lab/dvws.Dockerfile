# snoopysecurity/dvws-node @ 4221c04f (GPL-3.0): v5 FINAL HELD-OUT app (FREEZE_v5.json). LAB ONLY, 127.0.0.1 only.
# Upstream Dockerfile (node:22, npm install, Svelte frontend build, port 80 as root). Here: node:22-bookworm-slim,
# `npm ci` from the shipped package-lock.json, no frontend build (the scan uses the REST API; public/ ships a static
# index.html), port 8080 as the unprivileged `node` user. Same start command as upstream compose: seed, then start.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /home/dvws-node
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN chown -R node:node /home/dvws-node
USER node
ENV EXPRESS_JS_PORT=8080
EXPOSE 8080
CMD ["sh", "-c", "node scripts/seed-database.js && npm start"]
