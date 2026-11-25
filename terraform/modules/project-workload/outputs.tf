output "repository_url" { value = aws_ecr_repository.this.repository_url }
output "role_arn" { value = aws_iam_role.irsa.arn }
output "secret_name" { value = aws_secretsmanager_secret.this.name }
output "secret_arn" { value = aws_secretsmanager_secret.this.arn }
output "log_group_name" { value = aws_cloudwatch_log_group.this.name }
output "service_account" { value = local.service_account }
output "namespace" { value = local.namespace }
