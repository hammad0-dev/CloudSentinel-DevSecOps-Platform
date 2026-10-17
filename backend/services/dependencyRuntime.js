const fs = require('fs');
const path = require('path');
const os = require('os');
function configuration(env = process.env) {
  const snap = (env.TRIVY_CMD || '').startsWith('/snap/');
  const common = path.join(os.homedir(), 'snap/trivy/common');
  const cache = env.TRIVY_CACHE_DIR || (snap ? path.join(common, 'cs-db-verified-3cj1v216/cache') : null);
  const checkoutRoot = path.resolve(env.DEP_CLONE_DIR || (snap ? path.join(common, 'dependency-checkouts') : env.CLONE_DIR || '/tmp/cloudsentinel-scans'));
  if (snap && (!checkoutRoot.startsWith(common + '/') || !cache || !path.resolve(cache).startsWith(common + '/'))) throw new Error('Snap Trivy requires private cache and checkout paths under snap/trivy/common');
  return { checkoutRoot, env: { ...env, ...(cache ? { TRIVY_CACHE_DIR: cache } : {}), TRIVY_NO_PROGRESS: 'true', ...(snap ? { TRIVY_SKIP_DB_UPDATE: 'true', TRIVY_SKIP_JAVA_DB_UPDATE: 'true', TRIVY_SKIP_CHECK_UPDATE: 'true', TRIVY_OFFLINE_SCAN: 'true' } : {}) } };
}
function coverage(root, report) {
  const manifests = [];
  const names = /^(package(-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile|requirements.*\.txt|Pipfile(\.lock)?|poetry\.lock|go\.(mod|sum)|Cargo\.(toml|lock)|Gemfile(\.lock)?|composer\.(json|lock)|packages\.lock\.json)$/;
  function walk(dir) { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { if (['.git','node_modules'].includes(e.name) || e.isSymbolicLink()) continue; const p=path.join(dir,e.name); if(e.isDirectory()) walk(p); else if(names.test(e.name)) manifests.push(path.relative(root,p)); } }
  walk(root);
  const packages=(report.Results || []).reduce((n,r)=>n+(r.Packages || []).length,0);
  return { manifests, packages, status: packages ? 'INVENTORY_PRESENT' : manifests.length ? 'MANIFESTS_WITHOUT_INVENTORY' : 'NO_SUPPORTED_MANIFESTS_OBSERVED' };
}
module.exports = { configuration, coverage };
