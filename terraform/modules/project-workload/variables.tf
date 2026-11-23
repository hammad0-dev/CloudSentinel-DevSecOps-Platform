variable "project_id" {
  type = number
  validation {
    condition     = var.project_id >= 1 && floor(var.project_id) == var.project_id && !contains([11, 13, 17], var.project_id)
    error_message = "project_id must be a positive integer and not a protected project (11, 13, 17)."
  }
}

variable "component" {
  type = string
  validation {
    condition     = contains(["app", "frontend", "backend"], var.component)
    error_message = "component must be app, frontend or backend."
  }
}

variable "env_names" {
  description = "Names (never values) of the runtime configuration keys stored in the secret."
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.env_names) <= 20 && alltrue([for n in var.env_names : can(regex("^[A-Z][A-Z0-9_]{0,63}$", n))])
    error_message = "env_names must be at most 20 names matching ^[A-Z][A-Z0-9_]{0,63}$."
  }
}

variable "oidc_provider_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:iam::229032674007:oidc-provider/oidc\\.eks\\.ap-south-1\\.amazonaws\\.com/id/[A-F0-9]{32}$", var.oidc_provider_arn))
    error_message = "oidc_provider_arn must be the shared cluster's OIDC provider in account 229032674007."
  }
}

variable "oidc_issuer_host" {
  type = string
  validation {
    condition     = can(regex("^oidc\\.eks\\.ap-south-1\\.amazonaws\\.com/id/[A-F0-9]{32}$", var.oidc_issuer_host))
    error_message = "oidc_issuer_host must be the shared cluster's issuer without https://."
  }
}

variable "account_id" {
  type    = string
  default = "229032674007"
  validation {
    condition     = var.account_id == "229032674007"
    error_message = "Only account 229032674007 is allowed."
  }
}

variable "region" {
  type    = string
  default = "ap-south-1"
  validation {
    condition     = var.region == "ap-south-1"
    error_message = "Only ap-south-1 is allowed."
  }
}

variable "log_retention_days" {
  type    = number
  default = 7
  validation {
    condition     = contains([1, 3, 5, 7, 14], var.log_retention_days)
    error_message = "log_retention_days must be 1, 3, 5, 7 or 14."
  }
}
