terraform {
  required_version = ">= 1.16.6, < 1.17.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100.0"
    }
  }
  # Bucket is intentionally unspecified: remote init requires approved settings.
  backend "s3" {
    region              = "ap-south-1"
    encrypt             = true
    use_lockfile        = true
    allowed_account_ids = ["229032674007"]
  }
}
provider "aws" {
  region              = "ap-south-1"
  #profile             = "cloudsentinel-dev"
  allowed_account_ids = ["229032674007"]
}
variable "project_id" { type = number }
variable "availability_zone" { type = string }
variable "environment" {
  type    = string
  default = "development"
}
variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}
variable "flow_log_destination_arn" {
  description = "Existing approved private S3 flow-log bucket ARN; no bucket creation here."
  type        = string
}
module "network" {
  source                   = "../../modules/aws-network"
  project_id               = var.project_id
  availability_zone        = var.availability_zone
  environment              = var.environment
  vpc_cidr                 = var.vpc_cidr
  flow_log_destination_arn = var.flow_log_destination_arn
}
output "network_ids" {
  description = "Non-secret AWS resource IDs only."
  value       = module.network
}
