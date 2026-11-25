# terraform/environments/aws-demo/aws-demo.tfvars - non-secret settings (committed on purpose).
# api_public_cidrs goes in the gitignored local.tfvars; alert_email only in TF_VAR_alert_email.
# Region ap-south-1 and account 229032674007 are pinned in main.tf. Cost: docs/eks-cost-gate.md.

cluster_name       = "cloudsentinel-eks"
kubernetes_version = "1.36" # standard support until 2027-08-02 (describe-cluster-versions, 2026-11-23)
vpc_cidr           = "10.40.0.0/16"
node_instance_type = "m7i-flex.large" # Free-plan eligible, 8 GiB; sized from the Minikube measurements
node_min_count     = 2
node_desired_count = 2
node_max_count     = 3
enable_guardduty   = false # SubscriptionRequiredException on the Free plan
