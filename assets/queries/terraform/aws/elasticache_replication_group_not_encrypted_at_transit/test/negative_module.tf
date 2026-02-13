module "user_example_redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 2.0"

  name = "cluster-example"

  engine_version = "3.2.10"
  node_type      = "cache.t2.small"
  number_cache_clusters = 2
  parameter_group_name = "default.redis3.2"

  port = 6379

  subnet_group_name = "${module.user_example_redis.cache_subnet_group_name}"
  family            = "${module.user_example_redis.cache_subnet_group_family}"

  maintenance_window = "sun:00:00-sun:03:00"
  notification_topic_arn = "arn:aws:sns:us-east-1:012345678900:my_sns_topic_name"

  security_group_ids = ["${module.sg.sg_id}"]

  transit_encryption_enabled = true

  apply_immediately     = true
  automatic_failover    = true
  auto_minor_version_upgrade = true

  tags = {
    Owner       = "user"
    Environment = "dev"
  }

  parameter {
    name  = "notify-keyspace-events"
    value = "Kg"
  }
}