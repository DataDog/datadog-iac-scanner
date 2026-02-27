---
title: "ElastiCache nodes not created across multi-AZ"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticache_nodes_not_created_across_multi_az"
  id: "cfdef2e5-1fe4-4ef4-bea8-c56e08963150"
  display_name: "ElastiCache nodes not created across multi-AZ"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Availability"
---
## Metadata

**Id:** `cfdef2e5-1fe4-4ef4-bea8-c56e08963150`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Availability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html)

### Description

Multi-node Amazon ElastiCache (Memcached) clusters must be deployed across multiple Availability Zones to maintain availability and avoid complete cluster outage if a single Availability Zone fails.
 
 The `AZMode` property on `AWS::ElastiCache::CacheCluster` must be set to `cross-az` for resources with `Engine` set to `memcached` and `NumCacheNodes` greater than `1`. If `AZMode` is omitted, the cluster defaults to `single-az`, so resources missing `AZMode` or with `AZMode` not equal to `cross-az` will be flagged as a configuration risk.

Secure configuration example:

```yaml
MyCacheCluster:
  Type: AWS::ElastiCache::CacheCluster
  Properties:
    Engine: memcached
    NumCacheNodes: 3
    AZMode: cross-az
    CacheNodeType: cache.m6g.large
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  myCacheCluster:
    Type: 'AWS::ElastiCache::CacheCluster'
    Properties:
      AZMode: cross-az
      CacheNodeType: cache.m3.medium
      Engine: memcached
      NumCacheNodes: '3'
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b

```

```json
{
  "Resources": {
    "myCacheCluster2": {
      "Type": "AWS::ElastiCache::CacheCluster",
      "Properties": {
        "AZMode": "cross-az",
        "CacheNodeType": "cache.m3.medium",
        "Engine": "memcached",
        "NumCacheNodes": "3",
        "PreferredAvailabilityZones": [
          "us-west-2a",
          "us-west-2a",
          "us-west-2b"
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  myCacheCluster4:
    Type: 'AWS::ElastiCache::CacheCluster'
    Properties:
      CacheNodeType: cache.m3.medium
      Engine: memcached
      NumCacheNodes: '3'
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b

```

```json
{
  "Resources": {
    "myCacheCluster5": {
      "Type": "AWS::ElastiCache::CacheCluster",
      "Properties": {
        "AZMode": "single-az",
        "CacheNodeType": "cache.m3.medium",
        "Engine": "memcached",
        "NumCacheNodes": "3",
        "PreferredAvailabilityZones": [
          "us-west-2a",
          "us-west-2a",
          "us-west-2b"
        ]
      }
    }
  }
}

```

```json
{
  "Resources": {
    "myCacheCluster6": {
      "Type": "AWS::ElastiCache::CacheCluster",
      "Properties": {
        "CacheNodeType": "cache.m3.medium",
        "Engine": "memcached",
        "NumCacheNodes": "3",
        "PreferredAvailabilityZones": [
          "us-west-2a",
          "us-west-2a",
          "us-west-2b"
        ]
      }
    }
  }
}

```