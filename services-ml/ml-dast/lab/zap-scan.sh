#!/usr/bin/env bash
# Run the UNMODIFIED zap-full-scan.py from the offline ZAP image against lab apps, on the lab's
# Docker network only (no host ports, no internet use: -silent disables update checks).
# Unauthenticated and without seed URLs: ZAP's own spider decides coverage.
# Reports: services-ml/ml-dast/logs/zap/<app>.json; scored by scripts/zap_compare.py.
# Usage: lab/zap-scan.sh app:port [app:port ...]   e.g. lab/zap-scan.sh labflask:8080
# Env (optional): ZAP_OUT (report dir, default logs/zap), ZAP_CONTEXT (a ZAP .context file in lab/, e.g.
#   zap-dsvw.context, which excludes DSVW parameters that execute code, fetch URLs or exhaust memory).
set -uo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
OUT="${ZAP_OUT:-$(cd "$LAB/.." && pwd)/logs/zap}"
IMAGE="cloudsentinel/zap-offline:verified-closure"
mkdir -p "$OUT" && chmod 777 "$OUT"
for t in "$@"; do
  name=${t%%:*}
  start=$(date +%s)
  rm -f "$OUT/$name.json"
  timeout 2400 docker run --rm --network mldast-lab_lab -v "$OUT:/zap/wrk:rw" "$IMAGE" \
    zap-full-scan.py -t "http://$t/" -m 3 -T 30 -I -J "$name.json" -z "-silent -config api.disablekey=true" > "$OUT/$name.log" 2>&1
  echo "$name exit=$? seconds=$(( $(date +%s) - start ))"
done
echo ALLDONE
