---
title: "ElastiCache with disabled at-rest encryption"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticache_with_disabled_at_rest_encryption"
  id: "e4ee3903-9225-4b6a-bdfb-e62dbadef821"
  display_name: "ElastiCache with disabled at-rest encryption"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `e4ee3903-9225-4b6a-bdfb-e62dbadef821`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-atrestencryptionenabled)

### Description

Amazon ElastiCache Redis replication groups must have encryption at rest enabled to protect cached data, snapshots, and backups from unauthorized access if storage media or snapshots are compromised. This can also help satisfy common data protection requirements.
 
 In CloudFormation, the `AWS::ElastiCache::ReplicationGroup` resource must define `AtRestEncryptionEnabled` and set it to `true` when the `Engine` property is `redis` (case-insensitive). Resources missing this property or with `AtRestEncryptionEnabled` set to `false` will be flagged. 
 
 Secure configuration example:

```yaml
MyRedisReplicationGroup:
  Type: AWS::ElastiCache::ReplicationGroup
  Properties:
    Engine: redis
    AtRestEncryptionEnabled: true
    ReplicationGroupDescription: "Secure Redis replication group with encryption at rest enabled"
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'State: ElastiCache redis, a cloudonaut.io template'
Resources:
  ReplicationGroup:
    DeletionPolicy: Snapshot
    UpdateReplacePolicy: Snapshot
    Type: AWS::ElastiCache::ReplicationGroup
    Properties:
      ReplicationGroupDescription: !Ref 'AWS::StackName'
      AtRestEncryptionEnabled: true
      AuthToken: !If [HasAuthToken, !Ref AuthToken, !Ref 'AWS::NoValue']
      AutomaticFailoverEnabled: !If [HasAutomaticFailoverEnabled, true, false]
      CacheNodeType: !Ref CacheNodeType
      CacheParameterGroupName: !Ref CacheParameterGroup
      CacheSubnetGroupName: !Ref CacheSubnetGroupName
      Engine: redis
      EngineVersion: !Ref EngineVersion
      KmsKeyId: !If [HasKmsKey, {'Fn::ImportValue': !Sub '${ParentKmsKeyStack}-KeyId'}, !Ref 'AWS::NoValue']
      NotificationTopicArn: !If [HasAlertTopic, {'Fn::ImportValue': !Sub '${ParentAlertStack}-TopicARN'}, !Ref 'AWS::NoValue']
      NumNodeGroups: !Ref NumShards
      ReplicasPerNodeGroup: !Ref NumReplicas
      PreferredMaintenanceWindow: 'sat:07:00-sat:08:00'
      SecurityGroupIds:
      - !Ref SecurityGroup
      SnapshotName: !If [HasSnapshotName, !Ref SnapshotName, !Ref 'AWS::NoValue']
      SnapshotRetentionLimit: !Ref SnapshotRetentionLimit
      SnapshotWindow: '00:00-03:00'
      TransitEncryptionEnabled: !Ref TransitEncryption
    UpdatePolicy:
      UseOnlineResharding: true

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "State: ElastiCache redis, a cloudonaut.io template",
  "Resources": {
    "ReplicationGroup": {
      "Properties": {
        "CacheParameterGroupName": "CacheParameterGroup",
        "EngineVersion": "EngineVersion",
        "KmsKeyId": [
          "HasKmsKey",
          {
            "Fn::ImportValue": "${ParentKmsKeyStack}-KeyId"
          },
          "AWS::NoValue"
        ],
        "ReplicasPerNodeGroup": "NumReplicas",
        "AuthToken": [
          "HasAuthToken",
          "AuthToken",
          "AWS::NoValue"
        ],
        "CacheNodeType": "CacheNodeType",
        "CacheSubnetGroupName": "CacheSubnetGroupName",
        "NotificationTopicArn": [
          "HasAlertTopic",
          {
            "Fn::ImportValue": "${ParentAlertStack}-TopicARN"
          },
          "AWS::NoValue"
        ],
        "SnapshotWindow": "00:00-03:00",
        "AutomaticFailoverEnabled": [
          "HasAutomaticFailoverEnabled",
          true,
          false
        ],
        "Engine": "redis",
        "NumNodeGroups": "NumShards",
        "SnapshotRetentionLimit": "SnapshotRetentionLimit",
        "ReplicationGroupDescription": "AWS::StackName",
        "PreferredMaintenanceWindow": "sat:07:00-sat:08:00",
        "SecurityGroupIds": [
          "SecurityGroup"
        ],
        "SnapshotName": [
          "HasSnapshotName",
          "SnapshotName",
          "AWS::NoValue"
        ],
        "TransitEncryptionEnabled": "TransitEncryption",
        "AtRestEncryptionEnabled": true
      },
      "UpdatePolicy": {
        "UseOnlineResharding": true
      },
      "DeletionPolicy": "Snapshot",
      "UpdateReplacePolicy": "Snapshot",
      "Type": "AWS::ElastiCache::ReplicationGroup"
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'State: ElastiCache redis, a cloudonaut.io template'
Resources:
  MyReplicationGroup:
    DeletionPolicy: Snapshot
    UpdateReplacePolicy: Snapshot
    Type: AWS::ElastiCache::ReplicationGroup
    Properties:
      ReplicationGroupDescription: !Ref 'AWS::StackName'
      AuthToken: !If [HasAuthToken, !Ref AuthToken, !Ref 'AWS::NoValue']
      AutomaticFailoverEnabled: !If [HasAutomaticFailoverEnabled, true, false]
      CacheNodeType: !Ref CacheNodeType
      CacheParameterGroupName: !Ref CacheParameterGroup
      CacheSubnetGroupName: !Ref CacheSubnetGroupName
      Engine: redis
      EngineVersion: !Ref EngineVersion
      KmsKeyId: !If [HasKmsKey, {'Fn::ImportValue': !Sub '${ParentKmsKeyStack}-KeyId'}, !Ref 'AWS::NoValue']
      NotificationTopicArn: !If [HasAlertTopic, {'Fn::ImportValue': !Sub '${ParentAlertStack}-TopicARN'}, !Ref 'AWS::NoValue']
      NumNodeGroups: !Ref NumShards
      ReplicasPerNodeGroup: !Ref NumReplicas
      PreferredMaintenanceWindow: 'sat:07:00-sat:08:00'
      SecurityGroupIds:
      - !Ref SecurityGroup
      SnapshotName: !If [HasSnapshotName, !Ref SnapshotName, !Ref 'AWS::NoValue']
      SnapshotRetentionLimit: !Ref SnapshotRetentionLimit
      SnapshotWindow: '00:00-03:00'
      TransitEncryptionEnabled: !Ref TransitEncryption
    UpdatePolicy:
      UseOnlineResharding: true

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "State: ElastiCache redis, a cloudonaut.io template",
  "Resources": {
    "ReplicationGroup": {
      "DeletionPolicy": "Snapshot",
      "UpdateReplacePolicy": "Snapshot",
      "Type": "AWS::ElastiCache::ReplicationGroup",
      "Properties": {
        "AutomaticFailoverEnabled": [
          "HasAutomaticFailoverEnabled",
          true,
          false
        ],
        "CacheNodeType": "CacheNodeType",
        "CacheParameterGroupName": "CacheParameterGroup",
        "CacheSubnetGroupName": "CacheSubnetGroupName",
        "EngineVersion": "EngineVersion",
        "AtRestEncryptionEnabled": false,
        "KmsKeyId": [
          "HasKmsKey",
          {
            "Fn::ImportValue": "${ParentKmsKeyStack}-KeyId"
          },
          "AWS::NoValue"
        ],
        "NotificationTopicArn": [
          "HasAlertTopic",
          {
            "Fn::ImportValue": "${ParentAlertStack}-TopicARN"
          },
          "AWS::NoValue"
        ],
        "SnapshotRetentionLimit": "SnapshotRetentionLimit",
        "TransitEncryptionEnabled": "TransitEncryption",
        "ReplicationGroupDescription": "AWS::StackName",
        "Engine": "redis",
        "ReplicasPerNodeGroup": "NumReplicas",
        "PreferredMaintenanceWindow": "sat:07:00-sat:08:00",
        "SecurityGroupIds": [
          "SecurityGroup"
        ],
        "SnapshotName": [
          "HasSnapshotName",
          "SnapshotName",
          "AWS::NoValue"
        ],
        "AuthToken": [
          "HasAuthToken",
          "AuthToken",
          "AWS::NoValue"
        ],
        "NumNodeGroups": "NumShards",
        "SnapshotWindow": "00:00-03:00"
      }
    }
  }
}

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "State: ElastiCache redis, a cloudonaut.io template",
  "Resources": {
    "MyReplicationGroup": {
      "Type": "AWS::ElastiCache::ReplicationGroup",
      "Properties": {
        "ReplicationGroupDescription": "AWS::StackName",
        "AutomaticFailoverEnabled": [
          "HasAutomaticFailoverEnabled",
          true,
          false
        ],
        "EngineVersion": "EngineVersion",
        "SecurityGroupIds": [
          "SecurityGroup"
        ],
        "SnapshotName": [
          "HasSnapshotName",
          "SnapshotName",
          "AWS::NoValue"
        ],
        "AuthToken": [
          "HasAuthToken",
          "AuthToken",
          "AWS::NoValue"
        ],
        "CacheParameterGroupName": "CacheParameterGroup",
        "CacheSubnetGroupName": "CacheSubnetGroupName",
        "NumNodeGroups": "NumShards",
        "PreferredMaintenanceWindow": "sat:07:00-sat:08:00",
        "SnapshotRetentionLimit": "SnapshotRetentionLimit",
        "CacheNodeType": "CacheNodeType",
        "KmsKeyId": [
          "HasKmsKey",
          {
            "Fn::ImportValue": "${ParentKmsKeyStack}-KeyId"
          },
          "AWS::NoValue"
        ],
        "NotificationTopicArn": [
          "HasAlertTopic",
          {
            "Fn::ImportValue": "${ParentAlertStack}-TopicARN"
          },
          "AWS::NoValue"
        ],
        "ReplicasPerNodeGroup": "NumReplicas",
        "Engine": "redis",
        "SnapshotWindow": "00:00-03:00",
        "TransitEncryptionEnabled": "TransitEncryption"
      },
      "UpdatePolicy": {
        "UseOnlineResharding": true
      },
      "DeletionPolicy": "Snapshot",
      "UpdateReplacePolicy": "Snapshot"
    }
  }
}

```