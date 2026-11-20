# node-api-goat (layro01 @ 868ee6c, ISC): v3 third-party TRAINING app. LAB ONLY, 127.0.0.1 only.
# Upstream ships no Dockerfile. Production dependencies only; the eval/deserialize/exec/file routes are
# on the ground-truth skip list and are never requested.
FROM node:18-bullseye-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY app ./app
USER node
EXPOSE 3001
CMD ["node", "app/server.js"]
