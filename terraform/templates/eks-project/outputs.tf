# Non-secret identifiers only. The generator reads these after apply to render the Kubernetes manifests.
output "components" {
  value = {
    for name, w in module.workload : name => {
      repository_url  = w.repository_url
      role_arn        = w.role_arn
      secret_name     = w.secret_name
      log_group_name  = w.log_group_name
      service_account = w.service_account
      namespace       = w.namespace
    }
  }
}

output "database" {
  value = length(module.database) == 0 ? null : {
    address                = module.database[0].address
    port                   = module.database[0].port
    db_name                = module.database[0].db_name
    engine                 = module.database[0].engine
    master_user_secret_arn = module.database[0].master_user_secret_arn
  }
}
