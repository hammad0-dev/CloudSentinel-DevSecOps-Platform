#!/usr/bin/env bash
# Fetch third-party lab app sources at pinned commits into lab/vendor/ (gitignored).
# The image-only apps (Juice Shop, DVNA) are pulled by docker compose; their digests are recorded
# in services-ml/ml-dast/data/dast/manifest.json.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vendor
fetch() {  # name url commit
  local dir="vendor/$1"
  if [[ ! -d "$dir/.git" ]]; then
    git init -q "$dir" && git -C "$dir" remote add origin "$2"
  fi
  git -C "$dir" fetch -q --depth 1 origin "$3"
  git -C "$dir" checkout -q --detach FETCH_HEAD
  echo "$1 $(git -C "$dir" rev-parse HEAD)"
}
fetch NodeGoat https://github.com/OWASP/NodeGoat.git c5cb68a7084e4ae7dcc60e6a98768720a81841e8
fetch vulpy https://github.com/fportantier/vulpy.git 5249cc8b05a1c37f6b2f757b1cf16a509c327122
fetch vulnerable-node https://github.com/cr0hn/vulnerable-node.git d68f2a3c9277ece2c2feb9976052033bdecd7fbe
fetch DSVW https://github.com/stamparm/DSVW.git 9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908  # v2 final held-out (FREEZE_v2.json)
