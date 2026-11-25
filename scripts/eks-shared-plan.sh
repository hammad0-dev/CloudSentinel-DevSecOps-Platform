#!/usr/bin/env bash
# Plan the shared EKS environment (terraform/environments/aws-demo) with profile cloudsentinel-admin. A plan is free.
# The alert address comes from TF_VAR_alert_email, else from ~/.config/cloudsentinel/alert-email (mode 600, outside
# the repo). It is never printed. Without either, the plan is saved as check-placeholder.tfplan and must not be applied.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../terraform/environments/aws-demo"
export AWS_PROFILE=cloudsentinel-admin AWS_PAGER=""
export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-/mnt/d/cs-data/tf-plugin-cache}"

ip=$(curl -s --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')
[[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "could not read the public IP" >&2; exit 1; }
printf 'api_public_cidrs = ["%s/32"]\n' "$ip" > local.tfvars   # gitignored

ef="$HOME/.config/cloudsentinel/alert-email"
if [[ -z "${TF_VAR_alert_email:-}" && -f "$ef" ]]; then
  TF_VAR_alert_email=$(head -1 "$ef" | tr -d '[:space:]'); export TF_VAR_alert_email
fi
if [[ -n "${TF_VAR_alert_email:-}" ]]; then out=shared.tfplan; echo "alert email: set"
else export TF_VAR_alert_email=alert-email-not-set@example.invalid; out=check-placeholder.tfplan
     echo "alert email: NOT set -> placeholder; plan saved as $out (never apply)"; fi

terraform fmt -check -recursive .
terraform init -input=false -lockfile=readonly >/dev/null
terraform validate -no-color >/dev/null
rm -f shared.tfplan check-placeholder.tfplan
terraform plan -input=false -no-color -var-file=aws-demo.tfvars -var-file=local.tfvars -out="$out" | grep -E '^(Plan:|Error)'
echo "$out sha256 $(sha256sum "$out" | cut -c1-64)"
