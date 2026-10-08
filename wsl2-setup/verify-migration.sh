#!/usr/bin/env bash
# CloudSentinel WSL2 Migration Verification
# Run: bash ~/CloudSentinel/wsl2-setup/verify-migration.sh

set -uo pipefail
BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; RESET='\033[0m'
ok()   { echo -e "  ${GREEN}✅  $*${RESET}"; }
fail() { echo -e "  ${RED}❌  $*${RESET}"; }
warn() { echo -e "  ${YELLOW}⚠️   $*${RESET}"; }
info() { echo -e "  ${CYAN}ℹ️   $*${RESET}"; }

PROJECT="/home/hammad/CloudSentinel"
PASS=0; FAIL=0

check() {
  local label="$1"; shift
  if "$@" &>/dev/null; then
    ok "${label}"
    ((PASS++)) || true
  else
    fail "${label}"
    ((FAIL++)) || true
  fi
}

echo ""
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  CloudSentinel WSL2 Migration Verification   ${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo ""

# ── 1. Filesystem ──────────────────────────────────────────────
echo -e "${BOLD}1. Filesystem${RESET}"
FS_TYPE="$(df -T "${PROJECT}" | awk 'NR==2{print $2}')"
if [[ "${FS_TYPE}" == "ext4" ]]; then
  ok "~/CloudSentinel is on ext4 (native WSL2, NOT Windows drvfs)"
  ((PASS++)) || true
else
  fail "~/CloudSentinel is on ${FS_TYPE} — expected ext4. It may still be pointing at the Windows drive!"
  ((FAIL++)) || true
fi
echo ""

# ── 2. Key source files present & non-empty ────────────────────
echo -e "${BOLD}2. Source files synced from Windows copy${RESET}"
FILES=(
  "backend/server.js"
  "backend/db.js"
  "backend/routes/auth.js"
  "backend/routes/sast/index.js"
  "backend/routes/sast/pipeline.js"
  "backend/routes/dependency.js"
  "backend/routes/projects.js"
  "frontend/src/utils/emailAllowedDomain.js"
  "frontend/src/pages/Login.jsx"
  "frontend/src/pages/Register.jsx"
  "frontend/src/pages/Dashboard.jsx"
  "frontend/src/pages/ProjectsPage.jsx"
  "frontend/src/pages/SASTResults.jsx"
  "frontend/src/context/AuthContext.jsx"
  "frontend/src/lib/api.js"
  "schema.sql"
)
for f in "${FILES[@]}"; do
  path="${PROJECT}/${f}"
  if [[ -f "${path}" ]] && [[ -s "${path}" ]]; then
    SIZE="$(wc -c < "${path}")"
    ok "${f}  (${SIZE} bytes)"
    ((PASS++)) || true
  else
    fail "${f}  — MISSING or empty!"
    ((FAIL++)) || true
  fi
done
echo ""

# ── 3. Email restriction fix ───────────────────────────────────
echo -e "${BOLD}3. Gmail-only bug removed${RESET}"
EMAIL_FILE="${PROJECT}/frontend/src/utils/emailAllowedDomain.js"
if grep -q "ALLOWED_DOMAIN.*gmail.com" "${EMAIL_FILE}" 2>/dev/null; then
  fail "emailAllowedDomain.js still has Gmail-only restriction — fix not applied!"
  ((FAIL++)) || true
else
  ok "emailAllowedDomain.js — any email accepted (Gmail restriction removed)"
  ((PASS++)) || true
fi
echo ""

# ── 4. .env files ─────────────────────────────────────────────
echo -e "${BOLD}4. Environment files${RESET}"
BACKEND_ENV="${PROJECT}/backend/.env"
FRONTEND_ENV="${PROJECT}/frontend/.env"

if [[ -f "${BACKEND_ENV}" ]]; then
  ok "backend/.env exists"
  ((PASS++)) || true
  SONAR_HOST="$(grep '^SONAR_HOST=' "${BACKEND_ENV}" | cut -d= -f2)"
  if [[ "${SONAR_HOST}" == "http://localhost:9000" ]]; then
    ok "SONAR_HOST=http://localhost:9000 (correct — no old VM IP)"
    ((PASS++)) || true
  else
    fail "SONAR_HOST=${SONAR_HOST} — should be http://localhost:9000"
    ((FAIL++)) || true
  fi
  SONAR_TOKEN="$(grep '^SONAR_TOKEN=' "${BACKEND_ENV}" | cut -d= -f2)"
  if [[ "${SONAR_TOKEN}" == "PASTE_SONAR_TOKEN_HERE" ]] || [[ -z "${SONAR_TOKEN}" ]]; then
    warn "SONAR_TOKEN is still placeholder — fill it in before running SAST scans"
    warn "  Get token: http://localhost:9000 → My Account → Security → Generate Tokens"
  else
    ok "SONAR_TOKEN is set"
    ((PASS++)) || true
  fi
  DB_USER="$(grep '^DB_USER=' "${BACKEND_ENV}" | cut -d= -f2)"
  if [[ "${DB_USER}" == "csuser" ]]; then
    ok "DB credentials: csuser@localhost:5432/cloudsentinel"
    ((PASS++)) || true
  else
    warn "DB_USER=${DB_USER} (expected csuser)"
  fi
  JWT="$(grep '^JWT_SECRET=' "${BACKEND_ENV}" | cut -d= -f2)"
  if [[ ${#JWT} -ge 32 ]]; then
    ok "JWT_SECRET set (${#JWT} chars)"
    ((PASS++)) || true
  else
    fail "JWT_SECRET missing or too short"
    ((FAIL++)) || true
  fi
else
  fail "backend/.env MISSING — run the setup script"
  ((FAIL++)) || true
fi

if [[ -f "${FRONTEND_ENV}" ]]; then
  ok "frontend/.env exists"
  ((PASS++)) || true
  grep -q "VITE_API_BASE_URL=http://localhost:3000/api" "${FRONTEND_ENV}" \
    && { ok "VITE_API_BASE_URL=http://localhost:3000/api"; ((PASS++)) || true; } \
    || { fail "VITE_API_BASE_URL missing or wrong"; ((FAIL++)) || true; }
  grep -q "VITE_GOOGLE_CLIENT_ID=" "${FRONTEND_ENV}" \
    && { ok "VITE_GOOGLE_CLIENT_ID set"; ((PASS++)) || true; } \
    || { warn "VITE_GOOGLE_CLIENT_ID missing (Google login won't work)"; }
else
  fail "frontend/.env MISSING"
  ((FAIL++)) || true
fi
echo ""

# ── 5. node_modules ───────────────────────────────────────────
echo -e "${BOLD}5. npm dependencies${RESET}"
if [[ -d "${PROJECT}/backend/node_modules" ]]; then
  COUNT="$(ls "${PROJECT}/backend/node_modules" | wc -l)"
  ok "backend/node_modules: ${COUNT} packages (Linux native)"
  ((PASS++)) || true
else
  fail "backend/node_modules missing — run: cd ~/CloudSentinel/backend && npm install"
  ((FAIL++)) || true
fi
if [[ -d "${PROJECT}/frontend/node_modules" ]]; then
  COUNT="$(ls "${PROJECT}/frontend/node_modules" | wc -l)"
  ok "frontend/node_modules: ${COUNT} packages (Linux native)"
  ((PASS++)) || true
else
  fail "frontend/node_modules missing — run: cd ~/CloudSentinel/frontend && npm install"
  ((FAIL++)) || true
fi
echo ""

# ── 6. PostgreSQL ─────────────────────────────────────────────
echo -e "${BOLD}6. PostgreSQL${RESET}"
if sudo service postgresql status 2>/dev/null | grep -q "online\|running"; then
  ok "PostgreSQL service is running"
  ((PASS++)) || true
  # Check database and tables exist
  TABLES="$(sudo -u postgres psql -d cloudsentinel -tc '\dt' 2>/dev/null \
    | awk '{print $3}' | grep -v '^\s*$' | tr '\n' ' ' || true)"
  if [[ -n "${TABLES}" ]]; then
    ok "cloudsentinel DB tables: ${TABLES}"
    ((PASS++)) || true
  else
    warn "cloudsentinel DB has no tables — run: bash ~/CloudSentinel/wsl2-setup/step2c-postgres-setup.sh"
  fi
else
  warn "PostgreSQL not running — start with: sudo service postgresql start"
fi
echo ""

# ── 7. SonarQube ──────────────────────────────────────────────
echo -e "${BOLD}7. SonarQube${RESET}"
SONAR_STATUS="$(curl -s http://localhost:9000/api/system/status 2>/dev/null || echo 'FAILED')"
if echo "${SONAR_STATUS}" | grep -q '"status":"UP"'; then
  VERSION="$(echo "${SONAR_STATUS}" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)"
  ok "SonarQube UP at http://localhost:9000  (version ${VERSION})"
  ((PASS++)) || true
else
  fail "SonarQube not reachable — start: docker run -d --name sonarqube -p 9000:9000 sonarqube:community"
  ((FAIL++)) || true
fi
echo ""

# ── 8. sonar-scanner CLI ──────────────────────────────────────
echo -e "${BOLD}8. sonar-scanner CLI${RESET}"
if command -v sonar-scanner &>/dev/null; then
  ok "sonar-scanner on PATH: $(which sonar-scanner)"
  ((PASS++)) || true
else
  warn "sonar-scanner not on PATH — SAST scans will fail"
  warn "  Install: download from https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/"
  warn "  Or run: bash ~/CloudSentinel/wsl2-setup/step2-project-setup.sh (section 6)"
fi
echo ""

# ── Summary ───────────────────────────────────────────────────
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Results: ${GREEN}${PASS} passed${RESET}  ${RED}${FAIL} failed${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo ""
if [[ ${FAIL} -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}✅ Migration looks complete! Start services:${RESET}"
  echo ""
  echo "  Terminal 1:  cd ~/CloudSentinel/backend && npm run dev"
  echo "  Terminal 2:  cd ~/CloudSentinel/frontend && npm run dev"
  echo "  Browser:     http://localhost:5173"
else
  echo -e "${YELLOW}${BOLD}⚠️  ${FAIL} check(s) need attention (see above).${RESET}"
fi
echo ""
