# Offline Trivy 0.52.2 database transfer

Run these commands on a separately approved networked machine. Do not use the WSL production cache as the download destination.

```sh
set -eu
mkdir -m 700 trivy-db-transfer && cd trivy-db-transfer
oras pull ghcr.io/aquasecurity/trivy-db:2 -a
oras manifest fetch ghcr.io/aquasecurity/trivy-db:2 > manifest.json
sha256sum manifest.json
```

Record the immutable digest from `manifest.json` (`config.digest`/manifest digest) and the SHA-256 of the exported archive. Export the pulled OCI artifact with the ORAS version used, for example:

```sh
oras pull -a ghcr.io/aquasecurity/trivy-db:2
# Rename the downloaded layer/archive deterministically after inspecting it.
mv db.tar.gz trivy-db-2.tar.gz
sha256sum trivy-db-2.tar.gz > trivy-db-2.tar.gz.sha256
```

Transfer `trivy-db-2.tar.gz` and its checksum through an approved private channel. On WSL, verify and stage without changing the production cache:

```sh
cd /home/hammad/CloudSentinel
sha256sum -c /path/to/trivy-db-2.tar.gz.sha256
node backend/scripts/import-trivy-db.js /path/to/trivy-db-2.tar.gz "$(cut -d' ' -f1 /path/to/trivy-db-2.tar.gz.sha256)" /tmp/trivy-db-staging
```

The staging result must contain `db/trivy.db` and `db/metadata.json`. Confirm compatibility with `/snap/bin/trivy --version` (0.52.x) before any installation. Keep the original cache unchanged until staging and a bounded offline scan succeed. Then run one scan with `--skip-db-update --skip-java-db-update --offline-scan --format json`; generate CycloneDX separately using the same staged cache. No download is performed by the WSL commands above.
