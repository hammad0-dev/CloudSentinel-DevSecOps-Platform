#!/usr/bin/env bash
# Rotate a CloudSentinel project secret in AWS Secrets Manager (Module 9).
# Writes a NEW random value for each given key as a new secret version. The value is generated in-process and
# passed to the AWS CLI on stdin; it is never printed, logged, written to disk or put on a command line.
# Output: secret id, new version id and a 12-character SHA-256 prefix per key (to compare with what a pod sees).
#
#   scripts/rotate-secret.sh --secret-id cloudsentinel/p-42/app --key APP_GREETING [--key OTHER] [--profile P] [--dry-run]
#
# Only secrets named cloudsentinel/p-<n>/<component> are accepted; protected projects 11, 13 and 17 are refused.
# Region is fixed to ap-south-1. Default profile: cloudsentinel-dev (needs secretsmanager:PutSecretValue).
# External Secrets Operator picks the new version up within its refreshInterval (1m in the generated manifests);
# the kubelet then updates the mounted file without a redeploy. Env vars change only on pod restart.
set -euo pipefail
secret="" profile="${AWS_PROFILE:-cloudsentinel-dev}" dry=0 keys=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --secret-id) secret="${2:?}"; shift 2 ;;
    --key) keys+=("${2:?}"); shift 2 ;;
    --profile) profile="${2:?}"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ "$secret" =~ ^cloudsentinel/p-([1-9][0-9]*)/(app|frontend|backend)$ ]] || { echo "secret id must be cloudsentinel/p-<n>/<app|frontend|backend>" >&2; exit 2; }
case "${BASH_REMATCH[1]}" in 11|13|17) echo "project ${BASH_REMATCH[1]} is protected" >&2; exit 2 ;; esac
[[ ${#keys[@]} -ge 1 && ${#keys[@]} -le 20 ]] || { echo "give 1-20 --key names" >&2; exit 2; }
for k in "${keys[@]}"; do [[ "$k" =~ ^[A-Z][A-Z0-9_]{0,63}$ ]] || { echo "bad key name $k" >&2; exit 2; }; done
[[ "$profile" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "bad profile" >&2; exit 2; }

# Python builds {"SecretId":..., "SecretString": "{\"KEY\": \"<random>\"}"} on its stdout (the pipe) and prints the
# hashes on stderr; nothing secret reaches the terminal.
gen() {
  python3 -I -c '
import base64, hashlib, json, os, sys
secret, keys = sys.argv[1], sys.argv[2:]
values = {k: base64.urlsafe_b64encode(os.urandom(24)).decode() for k in keys}
for k, v in values.items():
    sys.stderr.write(f"{k} sha256_12={hashlib.sha256(v.encode()).hexdigest()[:12]}\n")
sys.stdout.write(json.dumps({"SecretId": secret, "SecretString": json.dumps(values)}))
' "$secret" "${keys[@]}"
}

if [[ $dry -eq 1 ]]; then
  gen > /dev/null
  echo "dry run: would call aws secretsmanager put-secret-value --secret-id $secret --region ap-south-1 --profile $profile (value on stdin)"
  exit 0
fi
export AWS_PAGER=""
out=$(gen | aws secretsmanager put-secret-value --cli-input-json file:///dev/stdin --region ap-south-1 --profile "$profile" \
        --query '{id:Name,version:VersionId}' --output text 2>&1) || {
  if grep -qiE 'expired|sso|login' <<<"$out"; then echo "AWS login for profile $profile has expired: run aws login --profile $profile" >&2
  else echo "put-secret-value failed: $(sed -E 's/[A-Za-z0-9+/]{32,}/[REDACTED]/g' <<<"$out" | head -c 300)" >&2; fi
  exit 1; }
echo "rotated: $out"
