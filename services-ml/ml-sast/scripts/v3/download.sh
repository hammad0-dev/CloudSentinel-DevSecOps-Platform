#!/usr/bin/env bash
# ml-sast v3: resumable downloads of the external sources to D: (never to C:).
# Usage: scripts/v3/download.sh <name> <url> [md5]
#   Downloads <url> into /mnt/d/cs-data/sast-v3/<name>/ with curl -C - (resume), up to 3 attempts, then
#   verifies the publisher's MD5 when given and records SHA-256, size and date in SOURCE.download.txt.
# Data is never executed: this script only fetches bytes.
set -u
export HF_HOME=/mnt/d/cs-data/hf-cache TMPDIR=/mnt/d/cs-data/tmp PIP_CACHE_DIR=/mnt/d/cs-data/pip-cache
mkdir -p "$HF_HOME" "$TMPDIR" "$PIP_CACHE_DIR"
name=$1; url=$2; md5=${3:-}
dir=/mnt/d/cs-data/sast-v3/$name
mkdir -p "$dir"
file=$dir/$(basename "${url%%\?*}")

free_gb() { df -BG --output=avail "$1" | tail -1 | tr -dc 0-9; }
if [ "$(free_gb /mnt/c)" -lt 15 ] || [ "$(free_gb /mnt/d)" -lt 60 ]; then
  echo "STOP: free space C:$(free_gb /mnt/c)G D:$(free_gb /mnt/d)G below the limits (15 / 60 GB)"; exit 3
fi

ok=0
for attempt in 1 2 3; do
  echo "[$(date -u +%FT%TZ)] attempt $attempt: $url"
  if curl -fL -C - --retry 3 --retry-delay 10 -o "$file" "$url"; then ok=1; break; fi
  sleep 30
done
[ $ok = 1 ] || { echo "FAILED after 3 attempts: $url"; exit 2; }

got_md5=$(md5sum "$file" | cut -d' ' -f1)
sha=$(sha256sum "$file" | cut -d' ' -f1)
if [ -n "$md5" ] && [ "$got_md5" != "$md5" ]; then echo "MD5 MISMATCH: $got_md5 != $md5"; exit 4; fi
{
  echo "url: $url"
  echo "file: $file"
  echo "downloaded_utc: $(date -u +%FT%TZ)"
  echo "bytes: $(stat -c %s "$file")"
  echo "sha256: $sha"
  echo "md5: $got_md5${md5:+ (publisher MD5 $md5: verified)}"
} >> "$dir/SOURCE.download.txt"
echo "done: $file $(du -h "$file" | cut -f1) sha256=$sha"
