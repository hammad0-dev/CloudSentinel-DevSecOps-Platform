# CloudSentinel - per-project RDS database for two-tier and three-tier projects (Module 8/9).
# Private (no public access, private subnets only), encrypted storage, reachable only from the shared cluster's
# node security group on the engine port. manage_master_user_password = true: RDS generates the master
# password and keeps it in a Secrets Manager secret it manages, so no password is in Terraform code or state.
# Demo settings: 1-day backups, no final snapshot, no deletion protection (the run ends with terraform destroy).
# Fixed, reviewed template; the generator only writes validated values into terraform.tfvars.json.

locals {
  name = "cloudsentinel-p${var.project_id}-db"
  engines = {
    postgres = { version = "17.11", port = 5432 }
    mysql    = { version = "8.4.13", port = 3306 }
  }
  port = local.engines[var.engine].port
}

resource "aws_db_subnet_group" "this" {
  name        = local.name
  description = "Private subnets of the shared CloudSentinel EKS VPC"
  subnet_ids  = var.private_subnet_ids
}

resource "aws_security_group" "this" {
  name        = local.name
  description = "RDS for project ${var.project_id}: ${var.engine} from the EKS nodes only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "${var.engine} from the shared EKS node security group"
    from_port       = local.port
    to_port         = local.port
    protocol        = "tcp"
    security_groups = [var.node_security_group_id]
  }
  # No egress block: Terraform removes the default allow-all egress rule. RDS needs no outbound access.
}

resource "aws_db_instance" "this" {
  identifier     = local.name
  engine         = var.engine
  engine_version = local.engines[var.engine].version
  instance_class = var.instance_class
  db_name        = var.db_name
  username       = "csadmin"
  port           = local.port

  manage_master_user_password = true

  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = true

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.this.id]
  publicly_accessible    = false
  multi_az               = false

  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  apply_immediately                   = true
  copy_tags_to_snapshot               = true
  performance_insights_enabled        = false

  backup_retention_period  = 1
  delete_automated_backups = true
  skip_final_snapshot      = true
  deletion_protection      = false
}
