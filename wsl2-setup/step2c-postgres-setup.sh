#!/usr/bin/env bash
# Run this ONCE inside a real WSL2 terminal (not via wsl -e from Windows).
# Sets up the cloudsentinel database, user, and schema.
# Usage: bash ~/CloudSentinel/wsl2-setup/step2c-postgres-setup.sh

set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}[OK]${RESET}  $*"; }
info() { echo -e "${CYAN}[INFO]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }

info "Starting PostgreSQL..."
sudo service postgresql start
sleep 2

# Create role csuser
ROLE="$(sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='csuser';" | tr -d ' \n')"
if [[ "$ROLE" == "1" ]]; then
  warn "Role 'csuser' already exists."
else
  sudo -u postgres psql -c "CREATE ROLE csuser WITH LOGIN PASSWORD 'cspassword123';"
  ok "Role 'csuser' created."
fi

# Create database
DB="$(sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='cloudsentinel';" | tr -d ' \n')"
if [[ "$DB" == "1" ]]; then
  warn "Database 'cloudsentinel' already exists."
else
  sudo -u postgres psql -c "CREATE DATABASE cloudsentinel OWNER csuser;"
  ok "Database 'cloudsentinel' created."
fi

# PG15 schema + table grants
sudo -u postgres psql -d cloudsentinel -c "GRANT ALL ON SCHEMA public TO csuser;"
sudo -u postgres psql -d cloudsentinel -c "ALTER SCHEMA public OWNER TO csuser;"

# Apply schema if not yet applied
USERS="$(sudo -u postgres psql -d cloudsentinel -tc \
  "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='users';" | tr -d ' \n')"
if [[ "$USERS" == "1" ]]; then
  warn "Tables already exist — skipping schema.sql."
else
  sudo -u postgres psql -d cloudsentinel -f ~/CloudSentinel/schema.sql
  ok "schema.sql applied."
fi

# Grant privileges
sudo -u postgres psql -d cloudsentinel -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO csuser;"
sudo -u postgres psql -d cloudsentinel -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO csuser;"
sudo -u postgres psql -d cloudsentinel -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO csuser;"
sudo -u postgres psql -d cloudsentinel -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO csuser;"

# Create scan working directory
mkdir -p ~/cloudsentinel-scans
ok "CLONE_DIR: ~/cloudsentinel-scans"

# Show tables
TABLES="$(sudo -u postgres psql -d cloudsentinel -tc '\dt' 2>/dev/null | awk '{print $3}' | grep -v '^\s*$' | tr '\n' ' ')"
ok "Tables: ${TABLES}"

echo ""
echo -e "${GREEN}PostgreSQL setup complete.${RESET}"
echo ""
echo "Now fill in your SONAR_TOKEN:"
echo "  nano ~/CloudSentinel/backend/.env"
echo "  (set SONAR_TOKEN=<your token from localhost:9000>)"
echo ""
echo "Then start services in TWO separate terminals:"
echo "  Terminal 1:  cd ~/CloudSentinel/backend && npm run dev"
echo "  Terminal 2:  cd ~/CloudSentinel/frontend && npm run dev"
echo ""
echo "Open in Windows browser: http://localhost:5173"
