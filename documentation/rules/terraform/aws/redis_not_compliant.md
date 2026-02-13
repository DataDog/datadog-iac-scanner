---
title: "Redis not compliant"
group_id: "Terraform / AWS"
meta:
  name: "aws/redis_not_compliant"
  id: "254c932d-e3bf-44b2-bc9d-eb5fdb09f8d4"
  display_name: "Redis not compliant"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `254c932d-e3bf-44b2-bc9d-eb5fdb09f8d4`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#engine_version)

### Description

 This check ensures that AWS ElastiCache Redis clusters are using versions that comply with PCI DSS requirements. Older Redis versions (prior to 5.0.0) lack important security features such as encryption in transit, improved authentication, and vulnerability patches required for PCI DSS compliance. Using non-compliant Redis versions could lead to data breaches, non-compliance penalties, and compromise of sensitive information stored in the cache.

Non-compliant example:
```terraform
resource "aws_elasticache_cluster" "example" {
  cluster_id      = "cluster-example"
  engine          = "redis"
  engine_version  = "2.6.13"  // Non-compliant version
  // ... other configuration
}
```

Compliant example:
```terraform
resource "aws_elasticache_cluster" "example" {
  cluster_id      = "cluster-example"
  engine          = "redis"
  engine_version  = "5.0.0"  // Compliant version
  // ... other configuration
}
```


## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "aws_elasticache_cluster" "negative1" {
  cluster_id           = "cluster-example"
  engine               = "redis"
  node_type            = "cache.m4.large"
  num_cache_nodes      = 1
  engine_version       = "5.0.0"
  port                 = 6379
}

```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "aws_elasticache_cluster" "positive1" {
  cluster_id           = "cluster-example"
  engine               = "redis"
  node_type            = "cache.m4.large"
  num_cache_nodes      = 1
  engine_version       = "2.6.13"
  port                 = 6379
}

```