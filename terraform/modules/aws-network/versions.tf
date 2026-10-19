terraform {
  required_version = ">= 1.16.6, < 1.17.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100.0"
    }
  }
}
