# snyk-labs/nodejs-goof @ add14ba (Apache-2.0): v5x extra TRAINING data (stage 6). LAB ONLY, 127.0.0.1 only.
# Upstream: node:18.13.0, `npm update && npm install`. Here: node:18-bookworm-slim and `npm ci` from the shipped lock file
# (no dependency updates), same start command (npm start).
FROM node:18-bookworm-slim
WORKDIR /usr/src/goof
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN mkdir -p /tmp/extracted_files && chown -R node:node /usr/src/goof /tmp/extracted_files
USER node
EXPOSE 3001
CMD ["npm", "start"]
