# LAB ONLY: deliberately vulnerable app for ml-dast ground truth. Never deploy.
FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev --no-audit --no-fund
COPY app.js .
RUN mkdir -p /srv/files && chown node /srv/files
USER node
EXPOSE 8080
CMD ["node", "app.js"]
