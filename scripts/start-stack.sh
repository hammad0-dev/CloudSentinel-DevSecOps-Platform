#!/usr/bin/env bash
# Start the full CloudSentinel ML pipeline stack, in order:
#   1. Minikube (profile "minikube", the kubectl context the backend deploys staging apps to)
#   2. ml-sast v3 (ml-sast-v3-ensemble 3.0.0) on 127.0.0.1:8001, CodeBERT from the local HF cache on D:, offline
#   3. ml-dast v4 (ml-dast-lr 4.0.0) on 127.0.0.1:8002, allowlist = <minikube ip> + NodePort range
#   4. backend (npm start) on :3000, reading backend/.env (SAST_ENGINE=ml, DAST_ENGINE=ml, ...)
#
# Each step is skipped when that component is already up and correct, so the script is safe to re-run.
# Usage:
#   scripts/start-stack.sh            start whatever is not running
#   scripts/start-stack.sh --restart  stop ml-sast, ml-dast and the backend first, then start everything
#   scripts/start-stack.sh --status   only report what is running
#
# Env overrides (defaults match the current deployment):
#   CS_SAST_DIR      checkout with ml-sast v3 code + models/release_v3      (default ~/cs-sast)
#   CS_DAST_DIR      checkout with ml-dast v4 code + models/release_v4      (default ~/cs-dast)
#   CS_BACKEND_DIR   backend that serves :3000                               (default ~/CloudSentinel/backend)
#   CS_HF_HOME       Hugging Face cache holding microsoft/codebert-base     (default /mnt/d/cs-data/hf-cache)
#   CS_LOG_DIR       logs for ml-sast and ml-dast                           (default ~/cs-logs)
#   MINIKUBE_PROFILE                                                         (default minikube)
# The backend log stays at ~/backend.log (the previous one is kept as ~/backend.log.1).
# backend/.env is only checked, never printed or changed.
set -uo pipefail

CS_SAST_DIR="${CS_SAST_DIR:-$HOME/cs-sast}"
CS_DAST_DIR="${CS_DAST_DIR:-$HOME/cs-dast}"
CS_BACKEND_DIR="${CS_BACKEND_DIR:-$HOME/CloudSentinel/backend}"
CS_HF_HOME="${CS_HF_HOME:-/mnt/d/cs-data/hf-cache}"
CS_LOG_DIR="${CS_LOG_DIR:-$HOME/cs-logs}"
MINIKUBE_PROFILE="${MINIKUBE_PROFILE:-minikube}"
SAST_PORT=8001 DAST_PORT=8002 BACKEND_PORT=3000
SAST_MODEL_DIR="$CS_SAST_DIR/services-ml/ml-sast/models/release_v3"
DAST_MODEL_DIR="$CS_DAST_DIR/services-ml/ml-dast/models/release_v4"
EXPECT_SAST="ml-sast-v3-ensemble 3.0.0"
EXPECT_DAST="4.0.0"
MODE="${1:-start}"

say()  { printf '[stack] %s\n' "$*"; }
die()  { printf '[stack] ERROR: %s\n' "$*" >&2; exit 1; }
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

status() {
  say "minikube ($MINIKUBE_PROFILE): $(minikube status -p "$MINIKUBE_PROFILE" --format '{{.Host}}/{{.APIServer}}' 2>/dev/null || echo stopped)  ip=$(minikube ip -p "$MINIKUBE_PROFILE" 2>/dev/null || echo -)"
  say "ml-sast :$SAST_PORT  $(model_of $SAST_PORT || true)"
  say "ml-dast :$DAST_PORT  $(model_of $DAST_PORT || true)"
  say "backend :$BACKEND_PORT $(get $BACKEND_PORT/api/health || echo down)"
}

case "$MODE" in
  --status) status; exit 0 ;;
  --restart|start) ;;
  *) die "usage: $0 [--restart|--status]" ;;
esac

# ---- preflight ------------------------------------------------------------------------------------
for f in "$SAST_MODEL_DIR/model.joblib" "$DAST_MODEL_DIR/model.joblib" "$CS_BACKEND_DIR/.env" \
         "$CS_SAST_DIR/scripts/run-ml-sast.sh" "$CS_DAST_DIR/scripts/run-ml-dast.sh"; do
  [[ -f "$f" ]] || die "missing $f"
done
[[ -d "$CS_HF_HOME/hub/models--microsoft--codebert-base" ]] || die "CodeBERT not in $CS_HF_HOME (ml-sast v3 runs offline and cannot download it)"
docker info >/dev/null 2>&1 || die "Docker is not running (Minikube needs it): sudo systemctl start docker"
pg_isready -q -h localhost -p 5432 || die "PostgreSQL is not accepting connections on localhost:5432: sudo systemctl start postgresql"
# backend/.env must point the backend at both ML services; values are checked, not printed.
envval() { grep -E "^$1=" "$CS_BACKEND_DIR/.env" | tail -1 | cut -d= -f2- | tr -d '"'"'"'\r'; }
bad=()
[[ "$(envval SAST_ENGINE)" == ml ]] || bad+=(SAST_ENGINE=ml)
[[ "$(envval DAST_ENGINE)" == ml ]] || bad+=(DAST_ENGINE=ml)
[[ "$(envval ML_SAST_URL)" == "http://127.0.0.1:$SAST_PORT" ]] || bad+=(ML_SAST_URL=http://127.0.0.1:$SAST_PORT)
[[ "$(envval ML_DAST_URL)" == "http://127.0.0.1:$DAST_PORT" ]] || bad+=(ML_DAST_URL=http://127.0.0.1:$DAST_PORT)
[[ "$(envval ML_SAST_TIMEOUT_MS)" == 1800000 ]] || bad+=(ML_SAST_TIMEOUT_MS=1800000)
((${#bad[@]})) && die "backend/.env needs: ${bad[*]}"
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
  say "ml-sast: starting v3 on :$SAST_PORT (CodeBERT from $CS_HF_HOME, offline)"
  ( cd "$CS_SAST_DIR" && env \
      ML_SAST_MODEL_DIR="$SAST_MODEL_DIR" ML_SAST_PORT=$SAST_PORT \
      ML_SAST_VENV="$CS_SAST_DIR/services-ml/ml-sast/.venv" \
      HF_HOME="$CS_HF_HOME" HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_DATASETS_OFFLINE=1 \
      HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 NO_PROXY= \
      TMPDIR=/mnt/d/cs-data/tmp \
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
  say "ml-dast: starting v4 on :$DAST_PORT"
  ( cd "$CS_DAST_DIR" && env -u ML_DAST_ALLOWED_HOSTS -u ML_DAST_ALLOWED_PORTS \
      ML_DAST_MODEL_DIR="$DAST_MODEL_DIR" ML_DAST_PORT=$DAST_PORT \
      setsid nohup scripts/run-ml-dast.sh --minikube < /dev/null > "$CS_LOG_DIR/ml-dast.log" 2>&1 & )
  wait_for "ml-dast" 120 sh -c "curl -s --noproxy '*' -m 3 http://127.0.0.1:$DAST_PORT/health | grep -q trained"
  cur=$(model_of $DAST_PORT)
  [[ "$cur" == *" $EXPECT_DAST" ]] || die "ml-dast serves '$cur', expected version $EXPECT_DAST (see $CS_LOG_DIR/ml-dast.log)"
  say "ml-dast: $cur ($(grep -o 'allow hosts=.*' "$CS_LOG_DIR/ml-dast.log" | head -1))"
fi

# ---- 4. backend -----------------------------------------------------------------------------------
if get $BACKEND_PORT/api/health | grep -q '"ok":true'; then
  say "backend: already running on :$BACKEND_PORT (use --restart to reload backend/.env)"
else
  listening $BACKEND_PORT && die ":$BACKEND_PORT is taken but /api/health does not answer"
  [[ -f "$HOME/backend.log" ]] && mv -f "$HOME/backend.log" "$HOME/backend.log.1"
  say "backend: starting (nohup npm start > ~/backend.log)"
  ( cd "$CS_BACKEND_DIR" && setsid nohup npm start < /dev/null > "$HOME/backend.log" 2>&1 & )
  wait_for "backend" 60 sh -c "curl -s --noproxy '*' -m 3 http://127.0.0.1:$BACKEND_PORT/api/health | grep -q '\"ok\":true'"
  say "backend: up"
fi

status
say "logs: $CS_LOG_DIR/ml-sast.log  $CS_LOG_DIR/ml-dast.log  ~/backend.log"
