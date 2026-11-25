output "address" { value = aws_db_instance.this.address }
output "port" { value = aws_db_instance.this.port }
output "db_name" { value = aws_db_instance.this.db_name }
output "engine" { value = aws_db_instance.this.engine }
# ARN of the RDS-managed secret holding the master username and password (value never exposed here).
output "master_user_secret_arn" { value = aws_db_instance.this.master_user_secret[0].secret_arn }
