---
title: "ElastiCache Redis cluster without backup"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticache_redis_cluster_without_backup"
  id: "8fdb08a0-a868-4fdf-9c27-ccab0237f1ab"
  display_name: "ElastiCache Redis cluster without backup"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `8fdb08a0-a868-4fdf-9c27-ccab0237f1ab`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit)

### Description

ElastiCache Redis clusters should have the `snapshot_retention_limit` attribute set to a value greater than `0` to ensure that automatic backups are retained for disaster recovery and business continuity purposes. When `snapshot_retention_limit = 0` is specified or omitted, no snapshots are stored, which means data can be permanently lost in the event of accidental deletion, infrastructure failure, or corruption.

```
resource "aws_elasticache_cluster" "insecure" {
  cluster_id                = "cluster"
  engine                    = "redis"
  node_type                 = "cache.m5.large"
  num_cache_nodes           = 1
  snapshot_retention_limit  = 0
}
```

Setting a higher value, such as `snapshot_retention_limit = 5`, helps preserve data integrity by retaining the specified number of daily snapshots.

```
resource "aws_elasticache_cluster" "secure" {
  cluster_id                = "cluster"
  engine                    = "redis"
  node_type                 = "cache.m5.large"
  num_cache_nodes           = 1
  snapshot_retention_limit  = 5
}
```

## Compliant Code Examples
```terraform
resource "aws_elasticache_cluster" "negative1" {
  cluster_id           = "cluster"
  engine               = "redis"
  node_type            = "cache.m5.large"
  num_cache_nodes      = 1
  parameter_group_name = aws_elasticache_parameter_group.default.id

  snapshot_retention_limit = 5
}

resource "aws_elasticache_parameter_group" "default" {
  name   = "cache-params"
  family = "redis2.8"

  parameter {
    name  = "activerehashing"
    value = "yes"
  }

  parameter {
    name  = "min-slaves-to-write"
    value = "2"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_elasticache_cluster" "positive1" {
  cluster_id           = "cluster"
  engine               = "redis"
  node_type            = "cache.m5.large"
  num_cache_nodes      = 1
  parameter_group_name = aws_elasticache_parameter_group.default.id
}

resource "aws_elasticache_cluster" "positive2" {
  cluster_id           = "cluster"
  engine               = "redis"
  node_type            = "cache.m5.large"
  num_cache_nodes      = 1
  parameter_group_name = aws_elasticache_parameter_group.default.id

  snapshot_retention_limit = 0
}

resource "aws_elasticache_parameter_group" "default" {
  name   = "cache-params"
  family = "redis2.8"

  parameter {
    name  = "activerehashing"
    value = "yes"
  }

  parameter {
    name  = "min-slaves-to-write"
    value = "2"
  }
}

```