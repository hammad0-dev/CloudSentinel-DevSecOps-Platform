# terraform/environments/aws-demo - shared CloudSentinel EKS environment (Modules 8, 9, 10, 11).
# Created ONCE by the cloudsentinel-admin profile with the terraform CLI; per-project resources are applied by the
# backend (terraform/templates/eks-project) with the scoped cloudsentinel-dev profile.
#
#   cd terraform/environments/aws-demo
#   export AWS_PROFILE=cloudsentinel-admin TF_VAR_alert_email=...        # never commit the address
#   terraform init && terraform plan -var-file=aws-demo.tfvars -var-file=local.tfvars -out=shared.tfplan
#   (local.tfvars is gitignored and holds api_public_cidrs = ["<your ip>/32"])
#
# BILLABLE once applied (EKS control plane, 2 nodes, NAT gateway, CloudWatch ingestion, KMS). See docs/eks-cost-gate.md.
# Destroy: terraform destroy -var-file=aws-demo.tfvars -var-file=local.tfvars (after removing Kubernetes
# LoadBalancer Services, PVCs, Helm releases and Kyverno policies, see docs/eks-progress.md).
# Replaces the earlier unpinned wiring of modules/eks-cluster (us-east-1, Kubernetes 1.30), which is left unused.

terraform {
  required_version = ">= 1.16.6, < 1.17.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.70.0"
    }
  }
  # Local state (gitignored); backed up to /mnt/d/ml-backup/eks-state/shared/ after every apply.
}

provider "aws" {
  region              = "ap-south-1"
  allowed_account_ids = ["229032674007"]
  default_tags {
    tags = {
      Project     = "cloudsentinel"
      ProjectId   = "shared"
      Module      = "8-eks-shared"
      Environment = "development"
      ManagedBy   = "Terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account = data.aws_caller_identity.current.account_id
  azs     = ["ap-south-1a", "ap-south-1b"]
}

# ---- VPC: 2 AZs, private subnets for nodes and RDS, public subnets for the NLB and the single NAT gateway ----
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.7.2"

  name = "${var.cluster_name}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  private_subnets = [cidrsubnet(var.vpc_cidr, 4, 0), cidrsubnet(var.vpc_cidr, 4, 1)]
  public_subnets  = [cidrsubnet(var.vpc_cidr, 8, 128), cidrsubnet(var.vpc_cidr, 8, 129)]

  enable_nat_gateway      = true
  single_nat_gateway      = true # cost: one NAT for both AZs
  enable_dns_hostnames    = true
  enable_dns_support      = true
  map_public_ip_on_launch = false

  # VPC Flow Logs to CloudWatch (Module 11)
  enable_flow_log                                 = true
  create_flow_log_cloudwatch_log_group            = true
  create_flow_log_cloudwatch_iam_role             = true
  flow_log_cloudwatch_log_group_retention_in_days = 7
  flow_log_max_aggregation_interval               = 60
  flow_log_traffic_type                           = "ALL"
  flow_log_cloudwatch_log_group_name_prefix       = "/cloudsentinel/vpc-flow-logs/"

  vpc_tags            = { "cloudsentinel/role" = "eks-shared-vpc" }
  private_subnet_tags = { "cloudsentinel/tier" = "private", "kubernetes.io/role/internal-elb" = "1" }
  public_subnet_tags  = { "cloudsentinel/tier" = "public", "kubernetes.io/role/elb" = "1" }
}

# ---- EKS --------------------------------------------------------------------------------------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "21.29.0"

  name               = var.cluster_name
  kubernetes_version = var.kubernetes_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  endpoint_public_access       = true
  endpoint_private_access      = true
  endpoint_public_access_cidrs = var.api_public_cidrs

  enable_cluster_creator_admin_permissions = true
  enable_irsa                              = true

  # Control-plane logs to CloudWatch (Module 11); Kubernetes secrets encrypted with a module-created KMS key.
  enabled_log_types                      = ["api", "audit", "authenticator"]
  cloudwatch_log_group_retention_in_days = 7

  addons = {
    vpc-cni        = { before_compute = true }
    kube-proxy     = {}
    coredns        = {}
    metrics-server = {}
    # No EBS CSI driver: nothing in the demo uses a PersistentVolumeClaim (Prometheus/Loki use emptyDir).
  }

  node_security_group_tags = { "cloudsentinel/role" = "eks-nodes" }

  eks_managed_node_groups = {
    default = {
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = [var.node_instance_type]
      capacity_type  = "ON_DEMAND"
      min_size       = var.node_min_count
      max_size       = var.node_max_count
      desired_size   = var.node_desired_count

      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 20
            volume_type           = "gp3"
            encrypted             = true
            delete_on_termination = true
          }
        }
      }
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 1 # pods cannot reach the node role through IMDS; they use IRSA
      }
      labels = { role = "cloudsentinel-workload" }
    }
  }
}
