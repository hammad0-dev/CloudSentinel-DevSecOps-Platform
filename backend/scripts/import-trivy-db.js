#!/usr/bin/env node
// Verify and stage an offline Trivy DB archive without touching the production cache.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const archive = process.argv[2];
const expectedSha = process.argv[3];
const outDir = process.argv[4] || '/tmp/cloudsentinel-trivy-staging';
if (!archive || !expectedSha || !/^[a-f0-9]{64}$/i.test(expectedSha)) {
  console.error('usage: import-trivy-db.js ARCHIVE SHA256 [STAGING_DIR]'); process.exit(2);
}
const archivePath = path.resolve(archive);
if (!fs.statSync(archivePath).isFile()) throw new Error('archive is not a file');
const sha = crypto.createHash('sha256').update(fs.readFileSync(archivePath)).digest('hex');
if (sha !== expectedSha.toLowerCase()) throw new Error(`archive SHA-256 mismatch: ${sha}`);
const listing = execFileSync('tar', ['-tf', archivePath], { encoding: 'utf8' }).trim().split('\n').filter(Boolean);
const rootLayout = listing.includes('trivy.db') && listing.includes('metadata.json');
const dbLayout = listing.includes('db/trivy.db') && listing.includes('db/metadata.json');
if (!rootLayout && !dbLayout) throw new Error('archive must contain trivy.db and metadata.json (at root or under db/)');
const required = rootLayout ? ['trivy.db', 'metadata.json'] : ['db/trivy.db', 'db/metadata.json'];
if (listing.some((item) => item.startsWith('/') || item.split('/').includes('..'))) throw new Error('unsafe archive path');
fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
execFileSync('tar', ['-xpf', archivePath, '-C', outDir, ...required]);
if (rootLayout) {
  fs.mkdirSync(path.join(outDir, 'db'), { mode: 0o700 });
  for (const name of ['trivy.db', 'metadata.json']) fs.renameSync(path.join(outDir, name), path.join(outDir, 'db', name));
}
for (const item of ['db/trivy.db', 'db/metadata.json']) fs.chmodSync(path.join(outDir, item), 0o600);
console.log(JSON.stringify({ sha256: sha, stagingDir: outDir, files: ['db/trivy.db', 'db/metadata.json'], productionCacheModified: false }));
