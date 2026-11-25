#!/usr/bin/env bash
# Start the full CloudSentinel ML pipeline stack, in order:
#   1. Minikube (profile "minikube", the kubectl context the backend deploys staging apps to)
#   2. ml-sast v3 (ml-sast-v3-ensemble 3.0.0) on 127.0.0.1:8001, CodeBERT from the local HF cache, offline
#   3. ml-dast v4 (ml-dast-lr 4.0.0) on 127.0.0.1:8002, allowlist = <minikube ip> + NodePort range
#   4. backend (npm start) on :3000, reading the backend .env (engines default to ml)
#
# Each step is skipped when that component is already up and correct, so the script is safe to re-run.
# Usage:
#   scripts/start-stack.sh            start whatever is not running
#   scripts/start-stack.sh --restart  stop ml-sast, ml-dast and the backend first, then start everything
#   scripts/start-stack.sh --status   report what is running and check the configuration (changes nothing)
#
# Paths. Code comes from the checkout this script is in (CS_ROOT = the directory above scripts/), so the
# script works from any clone or worktree. Model files, Python venvs and the backend .env are gitignored
# and machine-specific; they default to the same checkout and can be pointed elsewhere.
# Precedence: environment variable > config file > default.
#   Config file: $CS_STACK_ENV (default ~/.cloudsentinel-stack.env), KEY=VALUE lines, see
#   scripts/start-stack.env.example. It is parsed, never executed; only the keys below are read.
#
#   CS_ROOT            repository root                                    (default: parent of this script's dir)
#   CS_SAST_DIR        checkout whose services-ml/ml-sast code runs       (default $CS_ROOT)
#   CS_SAST_MODEL_DIR  model.joblib + model.json of ml-sast v3            (default $CS_SAST_DIR/services-ml/ml-sast/models/release_v3)
#   CS_SAST_VENV       Python venv for ml-sast                            (default $CS_SAST_DIR/services-ml/ml-sast/.venv)
#   CS_DAST_DIR        checkout whose services-ml/ml-dast code runs       (default $CS_ROOT)
#   CS_DAST_MODEL_DIR  model.joblib + model.json of ml-dast v4            (default $CS_DAST_DIR/services-ml/ml-dast/models/release_v4)
#   CS_DAST_VENV       Python venv for ml-dast                            (default $CS_DAST_DIR/services-ml/ml-dast/.venv)
#   CS_BACKEND_DIR     backend that serves :3000                          (default $CS_ROOT/backend)
#   CS_BACKEND_ENV     backend .env (passed as BACKEND_ENV_FILE)          (default $CS_BACKEND_DIR/.env)
#   CS_HF_HOME         Hugging Face cache with microsoft/codebert-base    (default /mnt/d/cs-data/hf-cache)
#   CS_TMPDIR          TMPDIR for ml-sast                                  (default /mnt/d/cs-data/tmp if it exists)
#   CS_LOG_DIR         logs for ml-sast and ml-dast                       (default ~/cs-logs)
#   MINIKUBE_PROFILE                                                       (default minikube)
# The backend log stays at ~/backend.log (the previous one is kept as ~/backend.log.1).
# The backend .env is only checked, never printed or changed.
set -uo pipefail

MODE="${1:-start}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_KEYS=" CS_ROOT CS_SAST_DIR CS_SAST_MODEL_DIR CS_SAST_VENV CS_DAST_DIR CS_DAST_MODEL_DIR CS_DAST_VENV CS_BACKEND_DIR CS_BACKEND_ENV CS_HF_HOME CS_TMPDIR CS_LOG_DIR MINIKUBE_PROFILE "

say()  { printf '[stack] %s\n' "$*"; }
die()  { printf '[stack] ERROR: %s\n' "$*" >&2; exit 1; }

# Config file: KEY=VALUE per line (# comments, optional quotes, leading ~ and $HOME expanded). A key that
# is already set in the environment wins. Nothing in the file is executed.
CS_STACK_ENV="${CS_STACK_ENV:-$HOME/.cloudsentinel-stack.env}"
CONFIG_USED="none"
if [[ -f "$CS_STACK_ENV" ]]; then
  CONFIG_USED="$CS_STACK_ENV"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    [[ "$line" =~ ^[[:space:]]*([A-Z_]+)=(.*)$ ]] || die "$CS_STACK_ENV: cannot parse line: $line"
    key="${BASH_REMATCH[1]}" value="${BASH_REMATCH[2]}"
    [[ "$STACK_KEYS" == *" $key "* ]] || die "$CS_STACK_ENV: unknown key $key (allowed:$STACK_KEYS)"
    value="${value%\"}" value="${value#\"}" value="${value%\'}" value="${value#\'}"
    [[ "$value" == "~" || "$value" == "~/"* ]] && value="$HOME${value#\~}"
    value="${value//\$HOME/$HOME}"
    [[ -z "${!key+x}" ]] && printf -v "$key" '%s' "$value"
  done < "$CS_STACK_ENV"
fi

CS_ROOT="${CS_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CS_SAST_DIR="${CS_SAST_DIR:-$CS_ROOT}"
CS_SAST_MODEL_DIR="${CS_SAST_MODEL_DIR:-$CS_SAST_DIR/services-ml/ml-sast/models/release_v3}"
CS_SAST_VENV="${CS_SAST_VENV:-$CS_SAST_DIR/services-ml/ml-sast/.venv}"
CS_DAST_DIR="${CS_DAST_DIR:-$CS_ROOT}"
CS_DAST_MODEL_DIR="${CS_DAST_MODEL_DIR:-$CS_DAST_DIR/services-ml/ml-dast/models/release_v4}"
CS_DAST_VENV="${CS_DAST_VENV:-$CS_DAST_DIR/services-ml/ml-dast/.venv}"
CS_BACKEND_DIR="${CS_BACKEND_DIR:-$CS_ROOT/backend}"
CS_BACKEND_ENV="${CS_BACKEND_ENV:-$CS_BACKEND_DIR/.env}"
CS_HF_HOME="${CS_HF_HOME:-/mnt/d/cs-data/hf-cache}"
if [[ -z "${CS_TMPDIR:-}" && -d /mnt/d/cs-data/tmp ]]; then CS_TMPDIR=/mnt/d/cs-data/tmp; fi
CS_TMPDIR="${CS_TMPDIR:-${TMPDIR:-/tmp}}"
CS_LOG_DIR="${CS_LOG_DIR:-$HOME/cs-logs}"
MINIKUBE_PROFILE="${MINIKUBE_PROFILE:-minikube}"
SAST_PORT=8001 DAST_PORT=8002 BACKEND_PORT=3000
EXPECT_SAST="ml-sast-v3-ensemble 3.0.0"
EXPECT_DAST="4.0.0"

get()  { curl -s --noproxy '*' -m "${2:-5}" "http://127.0.0.1:$1"; }
listening() { ss -ltn 2>/dev/null | grep -qE "[:.]$1\b"; }
pid_on() { ss -ltnp 2>/dev/null | grep -E "[:.]$1\b" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2; }
wait_for() {  # wait_for <description> <seconds> <command...>
  local what=$1 secs=$2; shift 2
  for ((i = 0; i < secs; i += 2)); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done
  die "$what did not come up within ${secs}s"
}
model_of() {  # "<name> <version>" from /model-info, empty if unreachable
  get "$1/model-info" 30 | python3 -I -c 'import json,sys
try: d=json.load(sys.stdin); print(d.get("name",""), d.get("version",""))
except Exception: pass' 2>/dev/null
}
stop_port() {
  local p; p=$(pid_on "$1")
  [[ -z "$p" ]] && return 0
  say "stopping $2 (pid $p on :$1)"
  pkill -TERM -P "$p" 2>/dev/null; kill "$p" 2>/dev/null
  for _ in $(seq 20); do listening "$1" || return 0; sleep 1; done
  die "$2 on :$1 did not stop"
}

# Read one key from the backend .env without printing the file.
envval() { grep -E "^$1=" "$CS_BACKEND_ENV" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"'\r'; }

# Configuration checks. Returns the problems found, one per line (empty = ready to start).
preflight() {
  local f
  for f in "$CS_SAST_MODEL_DIR/model.joblib" "$CS_SAST_MODEL_DIR/model.json" "$CS_DAST_MODEL_DIR/model.joblib" \
           "$CS_DAST_MODEL_DIR/model.json" "$CS_SAST_DIR/scripts/run-ml-sast.sh" "$CS_DAST_DIR/scripts/run-ml-dast.sh" \
           "$CS_SAST_DIR/services-ml/ml-sast/app.py" "$CS_DAST_DIR/services-ml/ml-dast/app.py" \
           "$CS_BACKEND_DIR/server.js" "$CS_BACKEND_ENV"; do
    [[ -f "$f" ]] || echo "missing $f"
  done
  # A missing venv would make run-ml-*.sh create one and pip-install into the checkout; require it instead.
  [[ -x "$CS_SAST_VENV/bin/python" ]] || echo "missing ml-sast venv $CS_SAST_VENV (set CS_SAST_VENV)"
  [[ -x "$CS_DAST_VENV/bin/python" ]] || echo "missing ml-dast venv $CS_DAST_VENV (set CS_DAST_VENV)"
  (cd "$CS_BACKEND_DIR" 2>/dev/null && node -e 'require.resolve("express")' >/dev/null 2>&1) \
    || echo "backend dependencies not installed for $CS_BACKEND_DIR (npm install)"
  [[ -d "$CS_HF_HOME/hub/models--microsoft--codebert-base" ]] \
    || echo "CodeBERT not in $CS_HF_HOME (ml-sast v3 runs offline and cannot download it; set CS_HF_HOME)"
  docker info >/dev/null 2>&1 || echo "Docker is not running (Minikube needs it): sudo systemctl start docker"
  pg_isready -q -h localhost -p 5432 || echo "PostgreSQL is not accepting connections on localhost:5432: sudo systemctl start postgresql"
  if [[ -f "$CS_BACKEND_ENV" ]]; then
    # Engines and timeout may be left out (code defaults: ml, ml, 1800000); if set, they must have these values.
    local v
    v=$(envval SAST_ENGINE); [[ -z "$v" || "$v" == ml ]] || echo "backend .env: SAST_ENGINE must be ml (or unset)"
    v=$(envval DAST_ENGINE); [[ -z "$v" || "$v" == ml ]] || echo "backend .env: DAST_ENGINE must be ml (or unset)"
    v=$(envval ML_SAST_TIMEOUT_MS); [[ -z "$v" || "$v" -ge 1800000 ]] 2>/dev/null || echo "backend .env: ML_SAST_TIMEOUT_MS must be at least 1800000 (or unset)"
    # The service URLs have no code default.
    [[ "$(envval ML_SAST_URL)" == "http://127.0.0.1:$SAST_PORT" ]] || echo "backend .env needs ML_SAST_URL=http://127.0.0.1:$SAST_PORT"
    [[ "$(envval ML_DAST_URL)" == "http://127.0.0.1:$DAST_PORT" ]] || echo "backend .env needs ML_DAST_URL=http://127.0.0.1:$DAST_PORT"
  fi
}

status() {
  say "minikube ($MINIKUBE_PROFILE): $(minikube status -p "$MINIKUBE_PROFILE" --format '{{.Host}}/{{.APIServer}}' 2>/dev/null || echo stopped)  ip=$(minikube ip -p "$MINIKUBE_PROFILE" 2>/dev/null || echo -)"
  say "ml-sast :$SAST_PORT  $(model_of $SAST_PORT || true)"
  say "ml-dast :$DAST_PORT  $(model_of $DAST_PORT || true)"
  say "backend :$BACKEND_PORT $(get $BACKEND_PORT/api/health || echo down)"
}

paths() {
  local k
  say "config file: $CONFIG_USED"
  for k in CS_ROOT CS_SAST_DIR CS_SAST_MODEL_DIR CS_SAST_VENV CS_DAST_DIR CS_DAST_MODEL_DIR CS_DAST_VENV CS_BACKEND_DIR CS_BACKEND_ENV CS_HF_HOME CS_TMPDIR CS_LOG_DIR; do
    say "  $(printf '%-17s' "$k") ${!k}  $([[ -e "${!k}" ]] && echo ok || echo MISSING)"
  done
}

case "$MODE" in
  --status)
    status
    paths
    problems=$(preflight)
    if [[ -z "$problems" ]]; then say "configuration: ready (a start or --restart would pass its checks)"
    else say "configuration: NOT ready"; while IFS= read -r p; do say "  - $p"; done <<< "$problems"; fi
    exit 0 ;;
  --restart|start) ;;
  *) die "usage: $0 [--restart|--status]" ;;
esac

# ---- preflight ------------------------------------------------------------------------------------
problems=$(preflight)
if [[ -n "$problems" ]]; then
  while IFS= read -r p; do printf '[stack] ERROR: %s\n' "$p" >&2; done <<< "$problems"
  die "configuration not ready (see scripts/start-stack.env.example; check with --status)"
fi
mkdir -p "$CS_LOG_DIR"

if [[ "$MODE" == --restart ]]; then
  stop_port $BACKEND_PORT backend
  stop_port $SAST_PORT ml-sast
  stop_port $DAST_PORT ml-dast
fi

# ---- 1. Minikube ----------------------------------------------------------------------------------
if [[ "$(minikube status -p "$MINIKUBE_PROFILE" --format '{{.APIServer}}' 2>/dev/null)" == Running ]]; then
  say "minikube: already running"
else
  say "minikube: starting profile $MINIKUBE_PROFILE"
  minikube start -p "$MINIKUBE_PROFILE" || die "minikube start failed"
fi
kubectl config use-context "$MINIKUBE_PROFILE" >/dev/null || die "no kubectl context $MINIKUBE_PROFILE"
wait_for "kubernetes API" 120 kubectl get --raw /readyz
say "minikube: ip $(minikube ip -p "$MINIKUBE_PROFILE")"

# ---- 2. ml-sast v3 --------------------------------------------------------------------------------
cur=$(model_of $SAST_PORT)
if [[ "$cur" == "$EXPECT_SAST" ]]; then
  say "ml-sast: already serving $cur"
else
  [[ -n "$cur" ]] && stop_port $SAST_PORT "ml-sast ($cur)"
  listening $SAST_PORT && die ":$SAST_PORT is taken by something that is not ml-sast"
  say "ml-sast: starting v3 on :$SAST_PORT from $CS_SAST_DIR (CodeBERT from $CS_HF_HOME, offline)"
  ( cd "$CS_SAST_DIR" && env \
      ML_SAST_MODEL_DIR="$CS_SAST_MODEL_DIR" ML_SAST_PORT=$SAST_PORT ML_SAST_VENV="$CS_SAST_VENV" \
      HF_HOME="$CS_HF_HOME" HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_DATASETS_OFFLINE=1 \
      HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 NO_PROXY= \
      TMPDIR="$CS_TMPDIR" \
      setsid nohup scripts/run-ml-sast.sh < /dev/null > "$CS_LOG_DIR/ml-sast.log" 2>&1 & )
  wait_for "ml-sast" 180 sh -c "curl -s --noproxy '*' -m 3 http://127.0.0.1:$SAST_PORT/health | grep -q trained"
  cur=$(model_of $SAST_PORT)
  [[ "$cur" == "$EXPECT_SAST" ]] || die "ml-sast serves '$cur', expected '$EXPECT_SAST' (see $CS_LOG_DIR/ml-sast.log)"
  say "ml-sast: $cur"
fi

# ---- 3. ml-dast v4 (allowlist taken from the running Minikube) ------------------------------------
cur=$(model_of $DAST_PORT)
if [[ "$cur" == *" $EXPECT_DAST" ]]; then
  say "ml-dast: already serving $cur (allowlist was set when it started; use --restart if the minikube ip changed)"
else
  [[ -n "$cur" ]] && stop_port $DAST_PORT "ml-dast ($cur)"
  listening $DAST_PORT && die ":$DAST_PORT is taken by something that is not ml-dast"
  say "ml-dast: starting v4 on :$DAST_PORT from $CS_DAST_DIR"
  ( cd "$CS_DAST_DIR" && env -u ML_DAST_ALLOWED_HOSTS -u ML_DAST_ALLOWED_PORTS \
      ML_DAST_MODEL_DIR="$CS_DAST_MODEL_DIR" ML_DAST_PORT=$DAST_PORT ML_DAST_VENV="$CS_DAST_VENV" \
      setsid nohup scripts/run-ml-dast.sh --minikube < /dev/null > "$CS_LOG_DIR/ml-dast.log" 2>&1 & )
  wait_for "ml-dast" 120 sh -c "curl -s --noproxy '*' -m 3 http://127.0.0.1:$DAST_PORT/health | grep -q trained"
  cur=$(model_of $DAST_PORT)
  [[ "$cur" == *" $EXPECT_DAST" ]] || die "ml-dast serves '$cur', expected version $EXPECT_DAST (see $CS_LOG_DIR/ml-dast.log)"
  say "ml-dast: $cur ($(grep -o 'allow hosts=.*' "$CS_LOG_DIR/ml-dast.log" | head -1))"
fi

# ---- 4. backend -----------------------------------------------------------------------------------
if get $BACKEND_PORT/api/health | grep -q '"ok":true'; then
  say "backend: already running on :$BACKEND_PORT (use --restart to reload the backend .env)"
else
  listening $BACKEND_PORT && die ":$BACKEND_PORT is taken but /api/health does not answer"
  [[ -f "$HOME/backend.log" ]] && mv -f "$HOME/backend.log" "$HOME/backend.log.1"
  say "backend: starting from $CS_BACKEND_DIR (nohup npm start > ~/backend.log)"
  ( cd "$CS_BACKEND_DIR" && BACKEND_ENV_FILE="$CS_BACKEND_ENV" setsid nohup npm start < /dev/null > "$HOME/backend.log" 2>&1 & )
  wait_for "backend" 60 sh -c "curl -s --noproxy '*' -m 3 http://127.0.0.1:$BACKEND_PORT/api/health | grep -q '\"ok\":true'"
  say "backend: up"
fi

status
say "logs: $CS_LOG_DIR/ml-sast.log  $CS_LOG_DIR/ml-dast.log  ~/backend.log"
