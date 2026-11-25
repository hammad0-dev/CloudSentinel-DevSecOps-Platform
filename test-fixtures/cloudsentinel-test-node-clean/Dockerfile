# Clean Node.js fixture. Non-root (numeric UID, matches the pod's runAsUser), production dependencies only,
# nothing written at runtime (works with readOnlyRootFilesystem). Base image pinned by digest (node 22.23.5, Alpine).
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY app.js ./
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]
USER 10001:10001
CMD ["node", "app.js"]
