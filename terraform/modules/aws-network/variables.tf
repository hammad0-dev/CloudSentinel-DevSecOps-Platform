variable "project_id" {
  description = "Explicitly approved project ID; existing protected projects 11/17 are excluded."
  type        = number
  validation {
    condition     = var.project_id > 0 && floor(var.project_id) == var.project_id && !contains([11, 17], var.project_id)
    error_message = "Use an approved positive integer project ID other than 11 or 17."
  }
}
variable "environment" {
  type    = string
  default = "development"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,19}$", var.environment))
    error_message = "Environment must be a short lowercase identifier."
  }
}
variable "availability_zone" {
  description = "Explicit enabled AZ in ap-south-1, verified before planning."
  type        = string
  validation {
    condition     = can(regex("^ap-south-1[a-z]$", var.availability_zone))
    error_message = "Select an enabled ap-south-1 AZ."
  }
}
variable "vpc_cidr" {
  description = "Private 10/8 IPv4 /16; public/private /24s are deterministically derived."
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && can(regex("^10\\.[0-9]+\\.0\\.0/16$", var.vpc_cidr))
    error_message = "Use a canonical private 10.x.0.0/16 IPv4 network."
  }
}
variable "flow_log_destination_arn" {
  description = "Existing, approved private SSE-encrypted S3 log bucket ARN; delivery policy/retention must be preconfigured separately."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.flow_log_destination_arn))
    error_message = "Provide an approved S3 bucket ARN, not a URL, wildcard or CloudWatch destination."
  }
}
