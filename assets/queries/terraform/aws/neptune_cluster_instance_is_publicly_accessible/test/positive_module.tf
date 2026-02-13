module "neptune" {
  source = "terraform-aws-modules/neptune/aws"
  version = "3.0.1"

  cluster_use_name_prefix = true
  name                = "neptune"
  engine_version      = "1.2.0.1"
  instance_type       = "db.r5.large"
  publicly_accessible = true
  autoscaling_enabled = true
  apply_immediately   = true

  create_db_cluster_parameter_group = true
  db_cluster_parameter_group_description = "DB Neptune cluster parameter group"
  db_cluster_parameter_group_parameters = [
    {
      name         = "neptune_query_timeout"
      value        = "20"
      apply_method = "immediate"
    }
  ]

  create_db_parameter_group = true
  db_parameter_group_description = "DB neptune instance parameter group"
  db_parameter_group_parameters = [
    {
      name         = "neptune_query_timeout"
      value        = "25"
      apply_method = "immediate"
    }
  ]
}