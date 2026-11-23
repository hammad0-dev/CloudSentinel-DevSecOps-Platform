# CloudSentinel - per-project root configuration for container projects on the shared EKS cluster.
# Fixed, reviewed template. The generator (backend/services/eksWorkload.js) copies this directory and the
# project-workload / project-database modules into a private job directory and writes ONLY validated values into
# terraform.tfvars.json. Nothing from the analysed repository is ever written into a .tf file.
#
# State: one local state file per project, path given at init time
#   terraform init -backend-config=path=<private dir>/<project>/eks/terraform.tfstate
# Account 229032674007 and region ap-south-1 are pinned here, not configurable.

terraform {
  required_version = ">= 1.16.6, < 1.17.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.70.0"
    }
  }
  backend "local" {}
}

provider "aws" {
  region              = "ap-south-1"
  allowed_account_ids = ["229032674007"]
  default_tags {
    tags = {
      Project     = "cloudsentinel"
      ProjectId   = tostring(var.project_id)
      Module      = "8-eks-workload"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# ---- shared cluster (created once by terraform/environments/aws-demo) ---------------------------------------
data "aws_eks_cluster" "shared" {
  name = var.cluster_name
}

data "aws_iam_openid_connect_provider" "shared" {
  url = data.aws_eks_cluster.shared.identity[0].oidc[0].issuer
}

data "aws_subnets" "private" {
  count = var.database.engine == "none" ? 0 : 1
  filter {
    name   = "vpc-id"
    values = [data.aws_eks_cluster.shared.vpc_config[0].vpc_id]
  }
  tags = {
    "cloudsentinel/tier" = "private"
  }
}

data "aws_security_group" "nodes" {
  count  = var.database.engine == "none" ? 0 : 1
  vpc_id = data.aws_eks_cluster.shared.vpc_config[0].vpc_id
  tags = {
    "cloudsentinel/role" = "eks-nodes"
  }
}

locals {
  oidc_issuer_host = replace(data.aws_eks_cluster.shared.identity[0].oidc[0].issuer, "https://", "")
}

# ---- per component: ECR, secret container, log group, IRSA role --------------------------------------------
module "workload" {
  source   = "../../modules/project-workload"
  for_each = var.components

  project_id         = var.project_id
  component          = each.key
  env_names          = each.value.env_names
  oidc_provider_arn  = data.aws_iam_openid_connect_provider.shared.arn
  oidc_issuer_host   = local.oidc_issuer_host
  log_retention_days = 7
}

# ---- two-tier / three-tier: private RDS ----------------------------------------------------------------------
module "database" {
  source = "../../modules/project-database"
  count  = var.database.engine == "none" ? 0 : 1

  project_id             = var.project_id
  engine                 = var.database.engine
  db_name                = var.database.name
  instance_class         = "db.t3.micro"
  vpc_id                 = data.aws_eks_cluster.shared.vpc_config[0].vpc_id
  private_subnet_ids     = data.aws_subnets.private[0].ids
  node_security_group_id = data.aws_security_group.nodes[0].id
}
