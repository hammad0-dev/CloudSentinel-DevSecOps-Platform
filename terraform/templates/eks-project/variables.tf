variable "project_id" {
  type = number
  validation {
    condition     = var.project_id >= 1 && floor(var.project_id) == var.project_id && !contains([11, 13, 17], var.project_id)
    error_message = "project_id must be a positive integer and not a protected project (11, 13, 17)."
  }
}

variable "environment" {
  type    = string
  default = "development"
  validation {
    condition     = var.environment == "development"
    error_message = "Only the development environment is supported."
  }
}

variable "cluster_name" {
  type = string
  validation {
    condition     = can(regex("^cloudsentinel-[a-z0-9-]{1,30}$", var.cluster_name))
    error_message = "cluster_name must match ^cloudsentinel-[a-z0-9-]{1,30}$."
  }
}

variable "components" {
  description = "Deployable components: {app} for one-tier/two-tier, {frontend, backend} for three-tier."
  type = map(object({
    port      = number
    env_names = list(string)
  }))
  validation {
    condition = (
      (length(var.components) == 1 && contains(keys(var.components), "app")) ||
      (length(var.components) == 2 && contains(keys(var.components), "frontend") && contains(keys(var.components), "backend"))
    )
    error_message = "components must be {app} or {frontend, backend}."
  }
  validation {
    condition     = alltrue([for c in values(var.components) : c.port >= 1024 && c.port <= 65535 && floor(c.port) == c.port])
    error_message = "Container ports must be unprivileged (1024-65535)."
  }
  validation {
    condition     = alltrue([for c in values(var.components) : length(c.env_names) <= 20 && alltrue([for n in c.env_names : can(regex("^[A-Z][A-Z0-9_]{0,63}$", n))])])
    error_message = "env_names must match ^[A-Z][A-Z0-9_]{0,63}$ (at most 20 per component)."
  }
}

variable "database" {
  type = object({
    engine = string
    name   = string
  })
  default = { engine = "none", name = "app" }
  validation {
    condition     = contains(["none", "postgres", "mysql"], var.database.engine) && can(regex("^[a-z][a-z0-9_]{0,30}$", var.database.name))
    error_message = "database.engine must be none, postgres or mysql and database.name must match ^[a-z][a-z0-9_]{0,30}$."
  }
}
