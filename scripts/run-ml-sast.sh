#!/usr/bin/env bash
# Start the ml-sast service (services-ml/ml-sast) with the v2 release model.
#
# The model files are gitignored. Put model.joblib and model.json from a training run
# (services-ml/ml-sast/models/release_v2/, produced by scripts/package_v2.py) into
# ML_SAST_MODEL_DIR first, e.g.:
#   mkdir -p services-ml/ml-sast/models/release_v2
#   cp /path/to/trained/release_v2/model.{joblib,json} services-ml/ml-sast/models/release_v2/
#
# Env (all optional):
#   ML_SAST_MODEL_DIR   folder with model.joblib + model.json (default services-ml/ml-sast/models/release_v2)
#   ML_SAST_VENV        Python venv to use (default services-ml/ml-sast/.venv; created from requirements.txt if missing)
#   ML_SAST_HOST        bind address (default 127.0.0.1)
#   ML_SAST_PORT        port (default 8001; the backend's ML_SAST_URL must match)
#   ML_SAST_CONFIDENCE_THRESHOLD  overrides the model's per-class thresholds
# Usage: scripts/run-ml-sast.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE="$ROOT/services-ml/ml-sast"
MODEL_DIR="${ML_SAST_MODEL_DIR:-$SERVICE/models/release_v2}"
VENV="${ML_SAST_VENV:-$SERVICE/.venv}"
HOST="${ML_SAST_HOST:-127.0.0.1}"
PORT="${ML_SAST_PORT:-8001}"

if [[ ! -f "$MODEL_DIR/model.joblib" ]]; then
  echo "run-ml-sast: no model at $MODEL_DIR/model.joblib" >&2
  echo "  Copy model.joblib and model.json from a training run (services-ml/ml-sast/models/release_v2/)" >&2
  echo "  into that folder, or set ML_SAST_MODEL_DIR. Without a model the service is 'untrained' and" >&2
  echo "  the backend refuses to use it." >&2
  exit 1
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "run-ml-sast: creating venv $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$SERVICE/requirements.txt"
fi

echo "run-ml-sast: http://$HOST:$PORT  model=$MODEL_DIR/model.joblib"
cd "$SERVICE"
MODEL_PATH="$MODEL_DIR/model.joblib" MODEL_META_PATH="$MODEL_DIR/model.json" \
  exec "$VENV/bin/python" -m uvicorn app:app --host "$HOST" --port "$PORT"
