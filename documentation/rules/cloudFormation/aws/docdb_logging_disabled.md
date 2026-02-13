---
title: "DocDB logging is disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/docdb_logging_disabled"
  id: "1bf3b3d4-f373-4d7c-afbb-7d85948a67a5"
  display_name: "DocDB logging is disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `1bf3b3d4-f373-4d7c-afbb-7d85948a67a5`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-enablecloudwatchlogsexports)

### Description

Amazon DocumentDB clusters must export profiler and audit logs to CloudWatch Logs to ensure visibility for security monitoring and to support incident response and compliance.
 
 The `EnableCloudwatchLogsExports` property on `AWS::DocDB::DBCluster` resources must be defined and include both `profiler` and `audit` in the list. Resources missing this property or omitting either value will be flagged because they prevent collection of critical diagnostic and audit data.

Secure configuration example:

```yaml
MyDocDBCluster:
  Type: AWS::DocDB::DBCluster
  Properties:
    DBClusterIdentifier: my-docdb-cluster
    MasterUsername: admin
    MasterUserPassword: SecretPassword123
    EnableCloudwatchLogsExports:
      - profiler
      - audit
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyDocDBCluster:
    Type: AWS::DocDB::DBCluster
    Properties:
      AvailabilityZones:
        - us-east-1a
        - us-east-1b
      BackupRetentionPeriod: 30
      CopyTagsToSnapshot: true
      DBClusterIdentifier: my-docdb-cluster
      DBClusterParameterGroupName: default.docdb3.6
      DBSubnetGroupName: my-docdb-subnet-group
      DeletionProtection: false
      EnableCloudwatchLogsExports:
        - error
        - general
        - profiler
        - audit
      EngineVersion: "3.6.0"
      KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
      MasterUsername: mydocdbuser
      MasterUserPassword: mysecretpassword123
      Port: 27017
      PreferredBackupWindow: "07:00-09:00"
      PreferredMaintenanceWindow: "sun:05:00-sun:06:00"
      StorageEncrypted: true
      Tags:
        - Key: Name
          Value: MyDocDBCluster
      UseLatestRestorableTime: true
      VpcSecurityGroupIds:
        - sg-0123456789abcdef0
        - sg-abcdef01234567890

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyDocDBCluster:
    Type: AWS::DocDB::DBCluster
    Properties:
      AvailabilityZones:
        - us-east-1a
        - us-east-1b
      BackupRetentionPeriod: 30
      CopyTagsToSnapshot: true
      DBClusterIdentifier: my-docdb-cluster
      DBClusterParameterGroupName: default.docdb3.6
      DBSubnetGroupName: my-docdb-subnet-group
      DeletionProtection: false
      EnableCloudwatchLogsExports: []
      EngineVersion: "3.6.0"
      KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
      MasterUsername: mydocdbuser
      MasterUserPassword: mysecretpassword123
      Port: 27017
      PreferredBackupWindow: "07:00-09:00"
      PreferredMaintenanceWindow: "sun:05:00-sun:06:00"
      StorageEncrypted: true
      Tags:
        - Key: Name
          Value: MyDocDBCluster
      UseLatestRestorableTime: true
      VpcSecurityGroupIds:
        - sg-0123456789abcdef0
        - sg-abcdef01234567890

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyDocDBCluster:
    Type: AWS::DocDB::DBCluster
    Properties:
      AvailabilityZones:
        - us-east-1a
        - us-east-1b
      BackupRetentionPeriod: 30
      CopyTagsToSnapshot: true
      DBClusterIdentifier: my-docdb-cluster
      DBClusterParameterGroupName: default.docdb3.6
      DBSubnetGroupName: my-docdb-subnet-group
      DeletionProtection: false
      EnableCloudwatchLogsExports:
        - error
        - general
        - profiler
      EngineVersion: "3.6.0"
      KmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
      MasterUsername: mydocdbuser
      MasterUserPassword: mysecretpassword123
      Port: 27017
      PreferredBackupWindow: "07:00-09:00"
      PreferredMaintenanceWindow: "sun:05:00-sun:06:00"
      StorageEncrypted: true
      Tags:
        - Key: Name
          Value: MyDocDBCluster
      UseLatestRestorableTime: true
      VpcSecurityGroupIds:
        - sg-0123456789abcdef0
        - sg-abcdef01234567890

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyDocDBCluster": {
      "Type": "AWS::DocDB::DBCluster",
      "Properties": {
        "AvailabilityZones": ["us-east-1a", "us-east-1b"],
        "BackupRetentionPeriod": 30,
        "CopyTagsToSnapshot": true,
        "DBClusterIdentifier": "my-docdb-cluster",
        "DBClusterParameterGroupName": "default.docdb3.6",
        "DBSubnetGroupName": "my-docdb-subnet-group",
        "DeletionProtection": false,
        "EnableCloudwatchLogsExports": ["error", "general", "audit"],
        "EngineVersion": "3.6.0",
        "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "MasterUsername": "mydocdbuser",
        "MasterUserPassword": "mysecretpassword123",
        "Port": 27017,
        "PreferredBackupWindow": "07:00-09:00",
        "PreferredMaintenanceWindow": "sun:05:00-sun:06:00",
        "StorageEncrypted": true,
        "Tags": [
          {
            "Key": "Name",
            "Value": "MyDocDBCluster"
          }
        ],
        "UseLatestRestorableTime": true,
        "VpcSecurityGroupIds": ["sg-0123456789abcdef0", "sg-abcdef01234567890"]
      }
    }
  }
}

```