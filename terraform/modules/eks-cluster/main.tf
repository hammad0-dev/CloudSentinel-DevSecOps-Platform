# terraform/modules/eks-cluster/main.tf
# CloudSentinel - EKS Cluster Module
# Minimal, cost-conscious cluster for demo purposes.
# DO NOT APPLY without reviewing aws-demo.tfvars cost implications.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ─── VPC (reuse existing or create minimal one) ────────────────────────────
data "aws_availability_zones" "available" { state = "available" }

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = var.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, 2)
  private_subnets = [cidrsubnet(var.vpc_cidr, 4, 0), cidrsubnet(var.vpc_cidr, 4, 1)]
  public_subnets  = [cidrsubnet(var.vpc_cidr, 4, 8), cidrsubnet(var.vpc_cidr, 4, 9)]

  enable_nat_gateway   = true
  single_nat_gateway   = true  # cost saving: 1 NAT instead of 1 per AZ
  enable_dns_hostnames = true

  tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    ManagedBy = "cloudsentinel"
  }
}

# ─── EKS Cluster ──────────────────────────────────────────────────────────
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = var.cluster_name
  cluster_version = var.kubernetes_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access = true

  eks_managed_node_groups = {
    cloudsentinel_nodes = {
      instance_types = [var.node_instance_type]
      min_size       = 1
      max_size       = 3
      desired_size   = var.node_desired_count

      labels = {
        role = "cloudsentinel-workload"
      }
    }
  }

  tags = {
    Environment = "cloudsentinel-demo"
    ManagedBy   = "terraform"
  }
}
