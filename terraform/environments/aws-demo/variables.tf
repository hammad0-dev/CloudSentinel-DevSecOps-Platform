variable "cluster_name" {
  type    = string
  default = "cloudsentinel-eks"
  validation {
    condition     = can(regex("^cloudsentinel-[a-z0-9-]{1,30}$", var.cluster_name))
    error_message = "cluster_name must match ^cloudsentinel-[a-z0-9-]{1,30}$."
  }
}

variable "kubernetes_version" {
  description = "EKS version in STANDARD support (checked with aws eks describe-cluster-versions on 2026-11-23)."
  type        = string
  validation {
    condition     = contains(["1.35", "1.36", "1.37"], var.kubernetes_version)
    error_message = "Use a version in standard support (1.35, 1.36 or 1.37 as of 2026-11-23); 1.30-1.33 are paid extended support."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && var.vpc_cidr != "10.0.0.0/16"
    error_message = "vpc_cidr must be a valid CIDR and must not overlap project 13's 10.0.0.0/16."
  }
}

variable "node_instance_type" {
  description = "Free-plan-eligible type (aws ec2 describe-instance-types --filters Name=free-tier-eligible,Values=true)."
  type        = string
  validation {
    condition     = contains(["m7i-flex.large", "c7i-flex.large", "t3.small", "t3.micro"], var.node_instance_type)
    error_message = "node_instance_type must be one of the Free-plan-eligible types listed in ap-south-1."
  }
}

variable "node_min_count" {
  type = number
}
variable "node_desired_count" {
  type = number
}
variable "node_max_count" {
  type = number
  validation {
    condition     = var.node_max_count <= 3
    error_message = "At most 3 nodes for the demo."
  }
}

variable "api_public_cidrs" {
  description = "CIDRs allowed to reach the public EKS API endpoint (your /32). Set in the gitignored local.tfvars."
  type        = list(string)
  validation {
    condition     = length(var.api_public_cidrs) > 0 && alltrue([for c in var.api_public_cidrs : can(cidrnetmask(c)) && c != "0.0.0.0/0"])
    error_message = "api_public_cidrs must be specific CIDRs, never 0.0.0.0/0."
  }
}

variable "alert_email" {
  description = "SNS email subscription for security alerts. Only from TF_VAR_alert_email; never committed or printed."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an email address."
  }
}

variable "enable_guardduty" {
  description = "GuardDuty detector + EKS audit-log monitoring (no EventBridge rule). Off: the Free plan answered SubscriptionRequiredException."
  type        = bool
  default     = false
}
