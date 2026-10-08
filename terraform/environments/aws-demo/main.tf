# terraform/environments/aws-demo/main.tf
# CloudSentinel AWS Demo Environment
# Wires the eks-cluster module with demo-specific settings.
# Run: terraform plan -var-file=aws-demo.tfvars
# DO NOT run terraform apply without reviewing costs first.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Uncomment to use remote state:
  # backend "s3" {
  #   bucket = "cloudsentinel-tfstate"
  #   key    = "aws-demo/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.aws_region
}

module "cloudsentinel_eks" {
  source = "../../modules/eks-cluster"

  cluster_name       = var.cluster_name
  kubernetes_version = var.kubernetes_version
  vpc_cidr           = var.vpc_cidr
  node_instance_type = var.node_instance_type
  node_desired_count = var.node_desired_count
}

variable "aws_region"         { type = string }
variable "cluster_name"       { type = string }
variable "kubernetes_version" { type = string }
variable "vpc_cidr"           { type = string }
variable "node_instance_type" { type = string }
variable "node_desired_count" { type = number }

output "cluster_endpoint" { value = module.cloudsentinel_eks.cluster_endpoint }
output "kubeconfig_command" { value = module.cloudsentinel_eks.kubeconfig_command }
