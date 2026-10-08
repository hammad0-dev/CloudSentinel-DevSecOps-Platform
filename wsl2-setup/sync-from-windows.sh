#!/usr/bin/env bash
# =============================================================================
#  CloudSentinel — Windows → WSL2 sync
#  Run this from a WSL2 terminal whenever you've made changes in the
#  Windows Antigravity IDE at D:\CloudSentinel-DevSecOps-Platform
#  and want those changes reflected in ~/CloudSentinel.
#
#  Usage:
#    bash ~/CloudSentinel/wsl2-setup/sync-from-windows.sh
#
#  What it syncs:  all source files (backend/, frontend/, schema.sql, etc.)
#  What it skips:  node_modules, .env files, .git history
# =============================================================================

WIN_SRC="/mnt/d/CloudSentinel-DevSecOps-Platform"
WSL_DST="/home/hammad/CloudSentinel"

# Verify Windows source is accessible
if [[ ! -d "${WIN_SRC}" ]]; then
  echo "❌  Windows source not found at ${WIN_SRC}"
  echo "   Is the D: drive mounted? Try: ls /mnt/d/"
  exit 1
fi

echo "🔄  Syncing ${WIN_SRC} → ${WSL_DST} ..."
echo "    (skipping: node_modules, .env, .git)"
echo ""

rsync -av --delete \
  --exclude='node_modules' \
  --exclude='.env' \
  --exclude='.env.*' \
  --exclude='.git' \
  --exclude='*.log' \
  "${WIN_SRC}/backend/"   "${WSL_DST}/backend/"

rsync -av --delete \
  --exclude='node_modules' \
  --exclude='.env' \
  --exclude='.env.*' \
  --exclude='.git' \
  --exclude='*.log' \
  "${WIN_SRC}/frontend/"  "${WSL_DST}/frontend/"

# Root-level files
for f in schema.sql package.json package-lock.json .gitignore README.md; do
  if [[ -f "${WIN_SRC}/${f}" ]]; then
    cp -u "${WIN_SRC}/${f}" "${WSL_DST}/${f}"
  fi
done

echo ""
echo "✅  Sync complete."
echo ""
echo "If you added/removed packages (package.json changed), also run:"
echo "  cd ~/CloudSentinel/backend  && npm install"
echo "  cd ~/CloudSentinel/frontend && npm install"
