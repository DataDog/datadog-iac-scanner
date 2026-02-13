---
title: "ElastiCache with disabled transit encryption"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticache_with_disabled_transit_encryption"
  id: "3b02569b-fc6f-4153-b3a3-ba91022fed68"
  display_name: "ElastiCache with disabled transit encryption"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `3b02569b-fc6f-4153-b3a3-ba91022fed68`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html)

### Description

 Amazon ElastiCache Redis replication groups must have in-transit encryption enabled to protect data exchanged between clients and cluster nodes from interception or tampering, preserving confidentiality and integrity.
 
 For CloudFormation resources of type `AWS::ElastiCache::ReplicationGroup` with `Engine` set to `redis`, the `TransitEncryptionEnabled` property must be defined and set to `true`. Resources missing `TransitEncryptionEnabled` or with `TransitEncryptionEnabled` set to `false` will be flagged as insecure. 
 
 Secure configuration example:

```yaml
MyRedisReplicationGroup:
  Type: AWS::ElastiCache::ReplicationGroup
  Properties:
    Engine: redis
    TransitEncryptionEnabled: true
    # other required properties...
```


## Compliant Code Examples
```yaml
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
      TransitEncryptionEnabled: true
    UpdatePolicy:
      UseOnlineResharding: true


```

```json
{
  "Resources": {
    "ReplicationGroup": {
      "UpdatePolicy": {
        "UseOnlineResharding": true
      },
      "DeletionPolicy": "Snapshot",
      "UpdateReplacePolicy": "Snapshot",
      "Type": "AWS::ElastiCache::ReplicationGroup",
      "Properties": {
        "AuthToken": [
          "HasAuthToken",
          "AuthToken",
          "AWS::NoValue"
        ],
        "AutomaticFailoverEnabled": [
          "HasAutomaticFailoverEnabled",
          true,
          false
        ],
        "SecurityGroupIds": [
          "SecurityGroup"
        ],
        "TransitEncryptionEnabled": true,
        "SnapshotWindow": "00:00-03:00",
        "CacheParameterGroupName": "CacheParameterGroup",
        "CacheSubnetGroupName": "CacheSubnetGroupName",
        "Engine": "redis",
        "EngineVersion": "EngineVersion",
        "KmsKeyId": [
          "HasKmsKey",
          {
            "Fn::ImportValue": "${ParentKmsKeyStack}-KeyId"
          },
          "AWS::NoValue"
        ],
        "SnapshotRetentionLimit": "SnapshotRetentionLimit",
        "ReplicationGroupDescription": "AWS::StackName",
        "ReplicasPerNodeGroup": "NumReplicas",
        "PreferredMaintenanceWindow": "sat:07:00-sat:08:00",
        "SnapshotName": [
          "HasSnapshotName",
          "SnapshotName",
          "AWS::NoValue"
        ],
        "AtRestEncryptionEnabled": true,
        "CacheNodeType": "CacheNodeType",
        "NotificationTopicArn": [
          "HasAlertTopic",
          {
            "Fn::ImportValue": "${ParentAlertStack}-TopicARN"
          },
          "AWS::NoValue"
        ],
        "NumNodeGroups": "NumShards"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
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
      AtRestEncryptionEnabled: true
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
      TransitEncryptionEnabled: false
    UpdatePolicy:
      UseOnlineResharding: true

```

```json
{
  "Resources": {
    "ReplicationGroup": {
      "Properties": {
        "Engine": "redis",
        "EngineVersion": "EngineVersion",
        "ReplicasPerNodeGroup": "NumReplicas",
        "PreferredMaintenanceWindow": "sat:07:00-sat:08:00",
        "AtRestEncryptionEnabled": true,
        "CacheParameterGroupName": "CacheParameterGroup",
        "NotificationTopicArn": [
          "HasAlertTopic",
          {
            "Fn::ImportValue": "${ParentAlertStack}-TopicARN"
          },
          "AWS::NoValue"
        ],
        "SecurityGroupIds": [
          "SecurityGroup"
        ],
        "SnapshotName": [
          "HasSnapshotName",
          "SnapshotName",
          "AWS::NoValue"
        ],
        "SnapshotRetentionLimit": "SnapshotRetentionLimit",
        "CacheNodeType": "CacheNodeType",
        "AutomaticFailoverEnabled": [
          "HasAutomaticFailoverEnabled",
          true,
          false
        ],
        "CacheSubnetGroupName": "CacheSubnetGroupName",
        "KmsKeyId": [
          "HasKmsKey",
          {
            "Fn::ImportValue": "${ParentKmsKeyStack}-KeyId"
          },
          "AWS::NoValue"
        ],
        "NumNodeGroups": "NumShards",
        "AuthToken": [
          "HasAuthToken",
          "AuthToken",
          "AWS::NoValue"
        ],
        "SnapshotWindow": "00:00-03:00",
        "ReplicationGroupDescription": "AWS::StackName"
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

```json
{
  "Resources": {
    "MyReplicationGroup": {
      "UpdateReplacePolicy": "Snapshot",
      "Type": "AWS::ElastiCache::ReplicationGroup",
      "Properties": {
        "ReplicationGroupDescription": "AWS::StackName",
        "AuthToken": [
          "HasAuthToken",
          "AuthToken",
          "AWS::NoValue"
        ],
        "EngineVersion": "EngineVersion",
        "NumNodeGroups": "NumShards",
        "SecurityGroupIds": [
          "SecurityGroup"
        ],
        "TransitEncryptionEnabled": false,
        "CacheNodeType": "CacheNodeType",
        "AtRestEncryptionEnabled": true,
        "NotificationTopicArn": [
          "HasAlertTopic",
          {
            "Fn::ImportValue": "${ParentAlertStack}-TopicARN"
          },
          "AWS::NoValue"
        ],
        "SnapshotName": [
          "HasSnapshotName",
          "SnapshotName",
          "AWS::NoValue"
        ],
        "AutomaticFailoverEnabled": [
          "HasAutomaticFailoverEnabled",
          true,
          false
        ],
        "Engine": "redis",
        "ReplicasPerNodeGroup": "NumReplicas",
        "PreferredMaintenanceWindow": "sat:07:00-sat:08:00",
        "SnapshotRetentionLimit": "SnapshotRetentionLimit",
        "SnapshotWindow": "00:00-03:00",
        "CacheParameterGroupName": "CacheParameterGroup",
        "CacheSubnetGroupName": "CacheSubnetGroupName",
        "KmsKeyId": [
          "HasKmsKey",
          {
            "Fn::ImportValue": "${ParentKmsKeyStack}-KeyId"
          },
          "AWS::NoValue"
        ]
      },
      "UpdatePolicy": {
        "UseOnlineResharding": true
      },
      "DeletionPolicy": "Snapshot"
    }
  }
}

```