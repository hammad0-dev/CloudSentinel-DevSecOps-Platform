# Module 9/11 shared security services: KMS, CloudTrail -> CloudWatch Logs, unauthorized-API-call alarm -> SNS email,
# optional GuardDuty (+ EventBridge -> SNS), the ESO IRSA role and the permissions boundary for project roles.

# ---- KMS key for the security pipeline (CloudTrail, its log group, SNS) -------------------------------------------
data "aws_iam_policy_document" "security_key" {
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account}:root"]
    }
  }
  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${local.account}:trail/*"]
    }
  }
  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.ap-south-1.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:ap-south-1:${local.account}:log-group:/cloudsentinel/*"]
    }
  }
  statement {
    sid       = "AlarmAndEventsPublishToEncryptedSns"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "security" {
  description             = "CloudSentinel security pipeline (CloudTrail, its log group, SNS alerts)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.security_key.json
}

resource "aws_kms_alias" "security" {
  name          = "alias/cloudsentinel-security"
  target_key_id = aws_kms_key.security.key_id
}

# ---- SNS topic + email subscription ------------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name              = "cloudsentinel-security-alerts"
  kms_master_key_id = aws_kms_key.security.arn
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid       = "AlarmsAndEvents"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

# The address comes only from TF_VAR_alert_email (sensitive; never in the repository, plans are gitignored).
# AWS emails a confirmation link; alerts are delivered only after it is clicked.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---- CloudTrail -> S3 (required by CloudTrail) and CloudWatch Logs -------------------------------------------------
resource "aws_s3_bucket" "trail" {
  bucket        = "cloudsentinel-trail-${local.account}-ap-south-1"
  force_destroy = true # demo: removed by terraform destroy
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "expire-demo-logs"
    status = "Enabled"
    filter {}
    expiration { days = 7 }
    noncurrent_version_expiration { noncurrent_days = 1 }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:ap-south-1:${local.account}:trail/cloudsentinel-trail"]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:ap-south-1:${local.account}:trail/cloudsentinel-trail"]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/cloudsentinel/cloudtrail"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.security.arn
}

data "aws_iam_policy_document" "trail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "trail_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role" "trail_logs" {
  name               = "cloudsentinel-cloudtrail-to-logs"
  assume_role_policy = data.aws_iam_policy_document.trail_assume.json
}

resource "aws_iam_role_policy" "trail_logs" {
  name   = "write-cloudtrail-log-group"
  role   = aws_iam_role.trail_logs.id
  policy = data.aws_iam_policy_document.trail_logs.json
}

resource "aws_cloudtrail" "this" {
  name                          = "cloudsentinel-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = aws_kms_key.security.arn
  is_multi_region_trail         = true # management events in every region, still the first (free) copy
  include_global_service_events = true # IAM/STS calls
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_logs.arn

  depends_on = [aws_s3_bucket_policy.trail]
}

# ---- Unauthorized / denied API calls -> alarm -> SNS email (CIS 4.1 pattern) ---------------------------------------
resource "aws_cloudwatch_log_metric_filter" "unauthorized" {
  name           = "cloudsentinel-unauthorized-api-calls"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  metric_transformation {
    name          = "UnauthorizedAPICalls"
    namespace     = "CloudSentinel/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized" {
  alarm_name          = "cloudsentinel-unauthorized-api-calls"
  alarm_description   = "One or more AWS API calls were denied (UnauthorizedOperation/AccessDenied) in the last 5 minutes"
  namespace           = "CloudSentinel/Security"
  metric_name         = "UnauthorizedAPICalls"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ---- GuardDuty (optional: the account answered SubscriptionRequiredException on the Free plan) ---------------------
resource "aws_guardduty_detector" "this" {
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "eks_audit" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "cloudsentinel-guardduty-findings"
  description = "GuardDuty findings to the CloudSentinel alert topic"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty" {
  count = var.enable_guardduty ? 1 : 0
  rule  = aws_cloudwatch_event_rule.guardduty[0].name
  arn   = aws_sns_topic.alerts.arn
}

# ---- External Secrets Operator IRSA role (shared by all projects: a known isolation limitation) -------------------
data "aws_iam_policy_document" "eso_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:sub"
      values   = ["system:serviceaccount:external-secrets:external-secrets"]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# LIMITATION: one role for every project. ESO in any namespace that a ClusterSecretStore admits can read every
# cloudsentinel/* secret and every RDS-managed master secret, so projects are not isolated from each other's
# secrets at the AWS layer. Mitigations here: only the platform creates ExternalSecrets (project RBAC cannot), and
# the ClusterSecretStore is limited to cloudsentinel-p-* namespaces. Per-project isolation would use a namespaced
# SecretStore authenticating as each project's own IRSA role (already created by project-workload).
data "aws_iam_policy_document" "eso" {
  statement {
    sid     = "ReadProjectSecrets"
    actions = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds"]
    resources = [
      "arn:aws:secretsmanager:ap-south-1:${local.account}:secret:cloudsentinel/*",
      "arn:aws:secretsmanager:ap-south-1:${local.account}:secret:rds!db-*",
    ]
  }
}

resource "aws_iam_role" "eso" {
  name               = "cloudsentinel-eso-irsa"
  description        = "External Secrets Operator (namespace external-secrets) reading cloudsentinel/* and RDS-managed secrets"
  assume_role_policy = data.aws_iam_policy_document.eso_assume.json
}

resource "aws_iam_role_policy" "eso" {
  name   = "read-cloudsentinel-secrets"
  role   = aws_iam_role.eso.id
  policy = data.aws_iam_policy_document.eso.json
}

# ---- Permissions boundary every per-project IRSA role must carry (see terraform/docs/policies) -------------------
data "aws_iam_policy_document" "workload_boundary" {
  statement {
    sid       = "ProjectSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = ["arn:aws:secretsmanager:ap-south-1:${local.account}:secret:cloudsentinel/*"]
  }
  statement {
    sid       = "ProjectLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:ap-south-1:${local.account}:log-group:/cloudsentinel/projects/*"]
  }
}

resource "aws_iam_policy" "workload_boundary" {
  name        = "cloudsentinel-workload-boundary"
  description = "Permissions boundary for per-project IRSA roles (cloudsentinel-p*-irsa)"
  policy      = data.aws_iam_policy_document.workload_boundary.json
}
