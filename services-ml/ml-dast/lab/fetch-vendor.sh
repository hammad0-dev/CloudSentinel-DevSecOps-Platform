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
fetch DSVW https://github.com/stamparm/DSVW.git 9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908  # v2 held-out (FREEZE_v2.json); v3 training
fetch sirappsec https://github.com/SirAppSec/vuln-node.js-express.js-app.git b977c7407f328da929577745ad509639e26c428a  # v3 final held-out (FREEZE_v3.json)
fetch VAmPI https://github.com/erev0s/VAmPI.git f16052dce83f05847133ec98f01c5193a41de7d8
fetch node-api-goat https://github.com/layro01/node-api-goat.git 868ee6c11a112d267b152f6dc8c50b8b4a11cdb7
fetch BenchmarkPython https://github.com/OWASP-Benchmark/BenchmarkPython.git f1291485808b66e20ddb6b01b10dc71b3df8c8ba  # v4 training (one LOAO group)
fetch dvpwa https://github.com/anxolerd/dvpwa.git 4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756  # v4 final held-out (FREEZE_v4.json)
fetch dvws-node https://github.com/snoopysecurity/dvws-node.git 4221c04f132960a0ccca4bf5aa5f3a9f53172778  # v5 final held-out (FREEZE_v5.json), login with the documented test account
fetch nodejs-goof https://github.com/snyk-labs/nodejs-goof.git add14ba59e98240d9e00a235dd7d42cd61ae9912  # v5x extra training data (stage 6), not a held-out
