variable "project_id" {
  type = number
  validation {
    condition     = var.project_id >= 1 && floor(var.project_id) == var.project_id && !contains([11, 13, 17], var.project_id)
    error_message = "project_id must be a positive integer and not a protected project (11, 13, 17)."
  }
}

variable "engine" {
  type = string
  validation {
    condition     = contains(["postgres", "mysql"], var.engine)
    error_message = "engine must be postgres or mysql; other databases need manual review."
  }
}

variable "db_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,30}$", var.db_name))
    error_message = "db_name must match ^[a-z][a-z0-9_]{0,30}$."
  }
}

variable "instance_class" {
  type    = string
  default = "db.t3.micro"
  validation {
    condition     = contains(["db.t3.micro"], var.instance_class)
    error_message = "Only db.t3.micro (Free-plan class orderable in ap-south-1) is allowed."
  }
}

variable "vpc_id" {
  type = string
  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "vpc_id must be a VPC id."
  }
}

variable "private_subnet_ids" {
  type = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2 && alltrue([for s in var.private_subnet_ids : can(regex("^subnet-[0-9a-f]{8,17}$", s))])
    error_message = "At least two private subnet ids are required."
  }
}

variable "node_security_group_id" {
  type = string
  validation {
    condition     = can(regex("^sg-[0-9a-f]{8,17}$", var.node_security_group_id))
    error_message = "node_security_group_id must be a security group id."
  }
}
