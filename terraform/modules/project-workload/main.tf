# CloudSentinel - per-project container workload (Module 8/9).
# One instance per deployable component (app | frontend | backend) of one project on the shared EKS cluster:
#   - ECR repository (scan on push, immutable tags, force_delete for the demo destroy)
#   - Secrets Manager secret that CONTAINS the runtime configuration keys. Terraform creates only the secret
#     container; it never writes a value, so no value is in Terraform code or state. Values are written
#     out of band (scripts/rotate-secret.sh) and reach the pod through External Secrets Operator.
#   - CloudWatch log group for the component
#   - IAM role for the component's Kubernetes service account (IRSA), allowed to read only its own secret
#     and write only to its own log group.
# This file is a fixed, reviewed template. The generator only writes validated values into terraform.tfvars.json.

locals {
  name_prefix     = "cloudsentinel-p${var.project_id}-${var.component}"
  namespace       = "cloudsentinel-p-${var.project_id}"
  service_account = "p${var.project_id}-${var.component}"
  secret_name     = "cloudsentinel/p-${var.project_id}/${var.component}"
  # Secrets Manager appends a 6-character suffix to secret ARNs; this pattern is known at plan time,
  # so the IAM policy below can be reviewed in the plan.
  secret_arn_pattern = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${local.secret_name}-??????"
  log_group_name     = "/cloudsentinel/projects/${var.project_id}/${var.component}"
  log_group_arn      = "arn:aws:logs:${var.region}:${var.account_id}:log-group:${local.log_group_name}"
}

resource "aws_ecr_repository" "this" {
  name                 = "cloudsentinel/p-${var.project_id}-${var.component}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_secretsmanager_secret" "this" {
  name                    = local.secret_name
  description             = length(var.env_names) > 0 ? "CloudSentinel runtime configuration keys: ${join(",", var.env_names)}" : "CloudSentinel runtime configuration (no keys detected)"
  recovery_window_in_days = 0
}

resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "assume" {
  statement {
    sid     = "ServiceAccountOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_issuer_host}:sub"
      values   = ["system:serviceaccount:${local.namespace}:${local.service_account}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_issuer_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "access" {
  statement {
    sid       = "ReadOwnSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [local.secret_arn_pattern]
  }

  statement {
    sid       = "WriteOwnLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${local.log_group_arn}:log-stream:*"]
  }
}

# The permissions boundary (created once by terraform/environments/aws-demo) caps what any project role can ever do,
# even if its inline policy were changed: read cloudsentinel/* secrets and write /cloudsentinel/* logs. The
# cloudsentinel-dev policy only allows CreateRole/PutRolePolicy when this boundary is attached.
resource "aws_iam_role" "irsa" {
  name                 = "${local.name_prefix}-irsa"
  description          = "IRSA role for ${local.namespace}/${local.service_account}"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = 3600
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/cloudsentinel-workload-boundary"
}

resource "aws_iam_role_policy" "irsa" {
  name   = "${local.name_prefix}-access"
  role   = aws_iam_role.irsa.id
  policy = data.aws_iam_policy_document.access.json
}
