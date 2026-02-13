---
title: "Neptune database cluster encryption disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/neptune_database_cluster_encryption_disabled"
  id: "bf4473f1-c8a2-4b1b-8134-bd32efabab93"
  display_name: "Neptune database cluster encryption disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `bf4473f1-c8a2-4b1b-8134-bd32efabab93`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster.html)

### Description

 Neptune DB cluster storage must be encrypted to protect data at rest, including cluster volumes, automated snapshots, and backups, from unauthorized access or disclosure. In AWS CloudFormation, the `StorageEncrypted` property on `AWS::Neptune::DBCluster` must be defined and set to `true`. Resources missing this property or with `StorageEncrypted` set to `false` will be flagged. Optionally specify a customer-managed KMS key with `KmsKeyId` if you need control over encryption keys.

Secure configuration example:

```yaml
MyNeptuneCluster:
  Type: AWS::Neptune::DBCluster
  Properties:
    StorageEncrypted: true
    KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-abcd-1234ef567890
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
  NeptuneDBCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      AssociatedRoles:
        - DBClusterRole
      AvailabilityZones:
        - String
      DBClusterIdentifier: String
      DBClusterParameterGroupName: String
      DBSubnetGroupName: String
      DeletionProtection: true
      EnableCloudwatchLogsExports:
        - String
      EngineVersion: String
      IamAuthEnabled: true
      KmsKeyId: String
      Port: 8182
      PreferredBackupWindow: String
      PreferredMaintenanceWindow: String
      RestoreToTime: String
      RestoreType: String
      SnapshotIdentifier: String
      SourceDBClusterIdentifier: String
      StorageEncrypted: true
      Tags:
        - Tag
      UseLatestRestorableTime: true
      VpcSecurityGroupIds:
        - String

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "NeptuneDBCluster": {
      "Type": "AWS::Neptune::DBCluster",
      "Properties": {
        "AvailabilityZones": [
          "String"
        ],
        "VpcSecurityGroupIds": [
          "String"
        ],
        "Tags": [
          "Tag"
        ],
        "EnableCloudwatchLogsExports": [
          "String"
        ],
        "EngineVersion": "String",
        "IamAuthEnabled": true,
        "KmsKeyId": "String",
        "PreferredMaintenanceWindow": "String",
        "RestoreToTime": "String",
        "SnapshotIdentifier": "String",
        "AssociatedRoles": [
          "DBClusterRole"
        ],
        "DBClusterIdentifier": "String",
        "DBClusterParameterGroupName": "String",
        "DeletionProtection": true,
        "Port": 8182,
        "PreferredBackupWindow": "String",
        "StorageEncrypted": true,
        "DBSubnetGroupName": "String",
        "RestoreType": "String",
        "SourceDBClusterIdentifier": "String",
        "UseLatestRestorableTime": true
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "NeptuneDBCluster": {
      "Type": "AWS::Neptune::DBCluster",
      "Properties": {
        "DBClusterIdentifier": "String",
        "EnableCloudwatchLogsExports": [
          "String"
        ],
        "EngineVersion": "String",
        "Port": 8182,
        "SourceDBClusterIdentifier": "String",
        "Tags": [
          "Tag"
        ],
        "AssociatedRoles": [
          "DBClusterRole"
        ],
        "DBSubnetGroupName": "String",
        "RestoreToTime": "String",
        "StorageEncrypted": false,
        "UseLatestRestorableTime": true,
        "DBClusterParameterGroupName": "String",
        "PreferredBackupWindow": "String",
        "SnapshotIdentifier": "String",
        "IamAuthEnabled": true,
        "DeletionProtection": true,
        "KmsKeyId": "String",
        "PreferredMaintenanceWindow": "String",
        "RestoreType": "String",
        "VpcSecurityGroupIds": [
          "String"
        ],
        "AvailabilityZones": [
          "String"
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template"
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
  NeptuneDBCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      AssociatedRoles:
        - DBClusterRole
      AvailabilityZones:
        - String
      DBClusterIdentifier: String
      DBClusterParameterGroupName: String
      DBSubnetGroupName: String
      DeletionProtection: true
      EnableCloudwatchLogsExports:
        - String
      EngineVersion: String
      IamAuthEnabled: true
      KmsKeyId: String
      Port: 8182
      PreferredBackupWindow: String
      PreferredMaintenanceWindow: String
      RestoreToTime: String
      RestoreType: String
      SnapshotIdentifier: String
      SourceDBClusterIdentifier: String
      StorageEncrypted: false
      Tags:
        - Tag
      UseLatestRestorableTime: true
      VpcSecurityGroupIds:
        - String

```