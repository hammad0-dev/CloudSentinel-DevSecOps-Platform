# terraform/environments/aws-demo/aws-demo.tfvars
# Cost-conscious demo configuration — do NOT apply without budget approval.
# Estimated cost: ~$0.10/hr for EKS control plane + ~$0.04/hr per t3.medium node

aws_region         = "us-east-1"
cluster_name       = "cloudsentinel-demo"
kubernetes_version = "1.30"
vpc_cidr           = "10.0.0.0/16"
node_instance_type = "t3.medium"
node_desired_count = 2
