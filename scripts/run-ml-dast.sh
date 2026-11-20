#!/usr/bin/env bash
# Start the ml-dast service (services-ml/ml-dast) with the trained model, as a HOST process.
#
# The model files are gitignored. Put model.joblib and model.json from a training run
# (services-ml/ml-dast/models/release/, produced by scripts/train_final.py) into ML_DAST_MODEL_DIR:
#   mkdir -p services-ml/ml-dast/models/release
#   cp /path/to/trained/release/model.{joblib,json} services-ml/ml-dast/models/release/
#
# Target allowlist for pipeline runs (ml-dast refuses every other target with HTTP 400):
#   --minikube (default): exactly the Minikube node IP (`minikube ip`) and the cluster's NodePort
#     range (kube-apiserver --service-node-port-range, default 30000-32767). The pipeline's staging
#     NodePort is assigned at deploy time, so this range is the narrowest static rule; no other host
#     is allowed, not even localhost.
#   --lab: the local lab (127.0.0.1/localhost, ports 5101-5108).
#   Or set ML_DAST_ALLOWED_HOSTS / ML_DAST_ALLOWED_PORTS yourself; the script then leaves them alone.
#
# Reachability: with Docker running natively in WSL/Linux, the Minikube bridge (192.168.49.0/24) is
# a local interface, so a host process reaches http://<minikube ip>:<NodePort> directly. (If ml-dast
# ran in a container instead, it would need `--network minikube`.)
#
# Env (optional): ML_DAST_MODEL_DIR, ML_DAST_VENV (default services-ml/ml-dast/.venv), ML_DAST_HOST
# (default 127.0.0.1), ML_DAST_PORT (default 8002; the backend's ML_DAST_URL must match),
# ML_DAST_RATE_PER_SEC, ML_DAST_CONFIDENCE_THRESHOLD.
# Usage: scripts/run-ml-dast.sh [--minikube|--lab]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE="$ROOT/services-ml/ml-dast"
MODEL_DIR="${ML_DAST_MODEL_DIR:-$SERVICE/models/release}"
VENV="${ML_DAST_VENV:-$SERVICE/.venv}"
HOST="${ML_DAST_HOST:-127.0.0.1}"
PORT="${ML_DAST_PORT:-8002}"
MODE="${1:---minikube}"

if [[ ! -f "$MODEL_DIR/model.joblib" ]]; then
  echo "run-ml-dast: no model at $MODEL_DIR/model.joblib" >&2
  echo "  Copy model.joblib and model.json from a training run (services-ml/ml-dast/models/release/)" >&2
  echo "  into that folder, or set ML_DAST_MODEL_DIR. Without a model the service is 'untrained'." >&2
  exit 1
fi

if [[ -z "${ML_DAST_ALLOWED_HOSTS:-}" && -z "${ML_DAST_ALLOWED_PORTS:-}" ]]; then
  case "$MODE" in
    --minikube)
      ip="$(minikube ip)"
      [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "run-ml-dast: minikube ip returned '$ip'" >&2; exit 1; }
      range="$(kubectl -n kube-system get pod -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null \
        | tr ',' '\n' | sed -n 's/.*--service-node-port-range=\([0-9]*-[0-9]*\).*/\1/p')"
      export ML_DAST_ALLOWED_HOSTS="$ip" ML_DAST_ALLOWED_PORTS="${range:-30000-32767}"
      ;;
    --lab)
      export ML_DAST_ALLOWED_HOSTS="127.0.0.1,localhost" ML_DAST_ALLOWED_PORTS="5101-5108"
      ;;
    *) echo "usage: $0 [--minikube|--lab]" >&2; exit 2 ;;
  esac
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "run-ml-dast: creating venv $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$SERVICE/requirements.txt"
fi

echo "run-ml-dast: http://$HOST:$PORT  model=$MODEL_DIR/model.joblib  allow hosts=$ML_DAST_ALLOWED_HOSTS ports=$ML_DAST_ALLOWED_PORTS"
cd "$SERVICE"
MODEL_PATH="$MODEL_DIR/model.joblib" MODEL_META_PATH="$MODEL_DIR/model.json" \
  exec "$VENV/bin/python" -m uvicorn app:app --host "$HOST" --port "$PORT"
