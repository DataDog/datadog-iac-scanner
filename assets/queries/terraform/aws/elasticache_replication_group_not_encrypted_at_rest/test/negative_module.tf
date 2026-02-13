module "elasticache_redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "2.0.0"

  identifier          = "democluster-redis"
  description         = "Redis"
  node_type           = "cache.t4g.small"
  num_cache_clusters  = 1
  engine_version      = "7.1"
  port                = 6379
  family              = "redis7"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  subnet_group_name          = "elasticache"
}
