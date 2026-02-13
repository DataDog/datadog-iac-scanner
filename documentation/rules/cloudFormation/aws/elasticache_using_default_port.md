---
title: "ElastiCache using default port"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticache_using_default_port"
  id: "323db967-c68e-44e6-916c-a777f95af34b"
  display_name: "ElastiCache using default port"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `323db967-c68e-44e6-916c-a777f95af34b`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-port)

### Description

Amazon ElastiCache replication groups must not use engine default ports because default ports are easily discovered and increase the risk of automated scanning, brute-force attempts, and unauthorized access.
 
 For `AWS::ElastiCache::ReplicationGroup` resources, ensure `Properties.Port` is not set to `6379` when `Properties.Engine` is `redis`, or to `11211` when `Properties.Engine` is `memcached`. Resources with those exact settings will be flagged.
 
 Choose a non-default `Port` value if you require obscurity, but do not rely on port choice alone. Also restrict access with security groups, subnet/VPC controls, and parameter group settings.
 
 Note that omitting the `Port` property typically causes the engine to use its default port. Explicitly configure a non-default port or enforce network-level restrictions to mitigate exposure.

Secure configuration example (CloudFormation YAML):

```yaml
MyReplicationGroup:
  Type: AWS::ElastiCache::ReplicationGroup
  Properties:
    Engine: redis
    Port: 6380
    ReplicationGroupId: my-redis-cluster
    ReplicationGroupDescription: "Redis cluster on non-default port"
```

## Compliant Code Examples
```yaml
Resources:
  BasicReplicationGroup:
    Type: 'AWS::ElastiCache::ReplicationGroup'
    Properties:
      AutomaticFailoverEnabled: true    
      CacheNodeType: cache.r3.large
      CacheSubnetGroupName: !Ref CacheSubnetGroup
      Engine: redis
      EngineVersion: '3.2'
      NumNodeGroups: '2'
      ReplicasPerNodeGroup: '3'
      Port: 6380
      PreferredMaintenanceWindow: 'sun:05:00-sun:09:00'
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
        - !Ref ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: '10:00-12:00' 

```

```json
{
  "Resources": {
    "BasicReplicationGroup": {
      "Type": "AWS::ElastiCache::ReplicationGroup",
      "Properties": {
          "AutomaticFailoverEnabled": true,            
          "CacheNodeType": "cache.r3.large",
          "CacheSubnetGroupName": {
              "Ref": "CacheSubnetGroup"
          },
          "Engine": "memcached",
          "EngineVersion": "3.2",
          "NumNodeGroups": "2",
          "ReplicasPerNodeGroup": "3",
          "Port": 11212,
          "PreferredMaintenanceWindow": "sun:05:00-sun:09:00",
          "ReplicationGroupDescription": "A sample replication group",
          "SecurityGroupIds": [
              {
                  "Ref": "ReplicationGroupSG"
              }
          ],
          "SnapshotRetentionLimit": 5,
          "SnapshotWindow": "10:00-12:00"
      }
    }
  }
}

```

```yaml
Resources:
  BasicReplicationGroup:
    Type: 'AWS::ElastiCache::ReplicationGroup'
    Properties:
      AutomaticFailoverEnabled: true    
      CacheNodeType: cache.r3.large
      CacheSubnetGroupName: !Ref CacheSubnetGroup
      Engine: memcached
      EngineVersion: '3.2'
      NumNodeGroups: '2'
      ReplicasPerNodeGroup: '3'
      Port: 11212
      PreferredMaintenanceWindow: 'sun:05:00-sun:09:00'
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
        - !Ref ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: '10:00-12:00' 

```
## Non-Compliant Code Examples
```yaml
Resources:
  BasicReplicationGroup:
    Type: 'AWS::ElastiCache::ReplicationGroup'
    Properties:
      AutomaticFailoverEnabled: true    
      CacheNodeType: cache.r3.large
      CacheSubnetGroupName: !Ref CacheSubnetGroup
      Engine: memcached
      EngineVersion: '3.2'
      NumNodeGroups: '2'
      ReplicasPerNodeGroup: '3'
      Port: 11211
      PreferredMaintenanceWindow: 'sun:05:00-sun:09:00'
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
        - !Ref ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: '10:00-12:00' 

```

```json
{
  "Resources": {
    "BasicReplicationGroup": {
      "Type": "AWS::ElastiCache::ReplicationGroup",
      "Properties": {
          "AutomaticFailoverEnabled": true,            
          "CacheNodeType": "cache.r3.large",
          "CacheSubnetGroupName": {
              "Ref": "CacheSubnetGroup"
          },
          "Engine": "redis",
          "EngineVersion": "3.2",
          "NumNodeGroups": "2",
          "ReplicasPerNodeGroup": "3",
          "Port": 6379,
          "PreferredMaintenanceWindow": "sun:05:00-sun:09:00",
          "ReplicationGroupDescription": "A sample replication group",
          "SecurityGroupIds": [
              {
                  "Ref": "ReplicationGroupSG"
              }
          ],
          "SnapshotRetentionLimit": 5,
          "SnapshotWindow": "10:00-12:00"
      }
    }
  }
}

```

```json
{
  "Resources": {
    "BasicReplicationGroup": {
      "Type": "AWS::ElastiCache::ReplicationGroup",
      "Properties": {
          "AutomaticFailoverEnabled": true,            
          "CacheNodeType": "cache.r3.large",
          "CacheSubnetGroupName": {
              "Ref": "CacheSubnetGroup"
          },
          "Engine": "memcached",
          "EngineVersion": "3.2",
          "NumNodeGroups": "2",
          "ReplicasPerNodeGroup": "3",
          "Port": 11211,
          "PreferredMaintenanceWindow": "sun:05:00-sun:09:00",
          "ReplicationGroupDescription": "A sample replication group",
          "SecurityGroupIds": [
              {
                  "Ref": "ReplicationGroupSG"
              }
          ],
          "SnapshotRetentionLimit": 5,
          "SnapshotWindow": "10:00-12:00"
      }
    }
  }
}

```