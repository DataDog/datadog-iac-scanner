---
title: "RDS storage encryption disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/rds_storage_encryption_disabled"
  id: "65844ba3-03a1-40a8-b3dd-919f122e8c95"
  display_name: "RDS storage encryption disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `65844ba3-03a1-40a8-b3dd-919f122e8c95`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html#cfn-rds-dbcluster-storageencrypted)

### Description

 RDS DB clusters must have storage encryption enabled to protect data at rest and to prevent exposure of database contents through compromised storage, snapshots, or automated backups. In AWS CloudFormation, the `StorageEncrypted` property on `AWS::RDS::DBCluster` resources must be defined and set to `true`. Resources missing `StorageEncrypted` or with `StorageEncrypted` set to `false` will be flagged. You can also specify a customer-managed KMS key using `KmsKeyId` if you require a specific CMK.

Secure configuration example:

```yaml
MyDBCluster:
  Type: AWS::RDS::DBCluster
  Properties:
    Engine: aurora-postgresql
    StorageEncrypted: true
    KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/abcd1234-56ef-78gh-90ij-klmnopqrstuv
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates RDS Cluster
Resources:
  RDSCluster:
    Properties:
      DBClusterParameterGroupName:
        Ref: RDSDBClusterParameterGroup
      DBSubnetGroupName: DBSubnetGroup
      Engine: aurora
      MasterUserPassword: password
      MasterUsername: username
      StorageEncrypted: true
    Type: "AWS::RDS::DBCluster"
  RDSDBClusterParameterGroup:
    Properties:
      Description: "CloudFormation Sample Aurora Cluster Parameter Group"
      Family: aurora5.6
      Parameters:
        time_zone: US/Eastern
    Type: "AWS::RDS::DBClusterParameterGroup"
  RDSDBInstance1:
    Properties:
      AvailabilityZone: eu-west-1b
      DBClusterIdentifier:
        Ref: RDSCluster
      DBInstanceClass: db.r3.xlarge
      DBParameterGroupName:
        Ref: RDSDBParameterGroup
      DBSubnetGroupName: DBSubnetGroup
      Engine: aurora
      PubliclyAccessible: "true"
    Type: "AWS::RDS::DBInstance"
  RDSDBInstance2:
    Properties:
      AvailabilityZone: eu-west-1b
      DBClusterIdentifier:
        Ref: RDSCluster
      DBInstanceClass: db.r3.xlarge
      DBParameterGroupName:
        Ref: RDSDBParameterGroup
      DBSubnetGroupName: DBSubnetGroup
      Engine: aurora
      PubliclyAccessible: "true"
    Type: "AWS::RDS::DBInstance"
  RDSDBParameterGroup:
    Type: 'AWS::RDS::DBParameterGroup'
    Properties:
      Description: CloudFormation Sample Aurora Parameter Group
      Family: aurora5.6
      Parameters:
        sql_mode: IGNORE_SPACE
        max_allowed_packet: 1024
        innodb_buffer_pool_size: '{DBInstanceClassMemory*3/4}'

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster",
  "Resources": {
    "RDSDBClusterParameterGroup": {
      "Properties": {
        "Description": "CloudFormation Sample Aurora Cluster Parameter Group",
        "Family": "aurora5.6",
        "Parameters": {
          "time_zone": "US/Eastern"
        }
      },
      "Type": "AWS::RDS::DBClusterParameterGroup"
    },
    "RDSDBInstance1": {
      "Properties": {
        "PubliclyAccessible": "true",
        "AvailabilityZone": "eu-west-1b",
        "DBClusterIdentifier": {
          "Ref": "RDSCluster"
        },
        "DBInstanceClass": "db.r3.xlarge",
        "DBParameterGroupName": {
          "Ref": "RDSDBParameterGroup"
        },
        "DBSubnetGroupName": "DBSubnetGroup",
        "Engine": "aurora"
      },
      "Type": "AWS::RDS::DBInstance"
    },
    "RDSDBInstance2": {
      "Properties": {
        "PubliclyAccessible": "true",
        "AvailabilityZone": "eu-west-1b",
        "DBClusterIdentifier": {
          "Ref": "RDSCluster"
        },
        "DBInstanceClass": "db.r3.xlarge",
        "DBParameterGroupName": {
          "Ref": "RDSDBParameterGroup"
        },
        "DBSubnetGroupName": "DBSubnetGroup",
        "Engine": "aurora"
      },
      "Type": "AWS::RDS::DBInstance"
    },
    "RDSDBParameterGroup": {
      "Type": "AWS::RDS::DBParameterGroup",
      "Properties": {
        "Description": "CloudFormation Sample Aurora Parameter Group",
        "Family": "aurora5.6",
        "Parameters": {
          "sql_mode": "IGNORE_SPACE",
          "max_allowed_packet": 1024,
          "innodb_buffer_pool_size": "{DBInstanceClassMemory*3/4}"
        }
      }
    },
    "RDSCluster": {
      "Properties": {
        "DBSubnetGroupName": "DBSubnetGroup",
        "Engine": "aurora",
        "MasterUserPassword": "password",
        "MasterUsername": "username",
        "StorageEncrypted": true,
        "DBClusterParameterGroupName": {
          "Ref": "RDSDBClusterParameterGroup"
        }
      },
      "Type": "AWS::RDS::DBCluster"
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates RDS Cluster
Resources:
  RDSCluster1:
    Properties:
      DBClusterParameterGroupName:
        Ref: RDSDBClusterParameterGroup
      DBSubnetGroupName: DBSubnetGroup
      Engine: aurora
      MasterUserPassword: password
      MasterUsername: username
    Type: "AWS::RDS::DBCluster"
  RDSDBClusterParameterGroup:
    Properties:
      Description: "CloudFormation Sample Aurora Cluster Parameter Group"
      Family: aurora5.6
      Parameters:
        time_zone: US/Eastern
    Type: "AWS::RDS::DBClusterParameterGroup"
  RDSDBInstance1:
    Properties:
      AvailabilityZone: eu-west-1b
      DBClusterIdentifier:
        Ref: RDSCluster
      DBInstanceClass: db.r3.xlarge
      DBParameterGroupName:
        Ref: RDSDBParameterGroup
      DBSubnetGroupName: DBSubnetGroup
      Engine: aurora
      PubliclyAccessible: "true"
    Type: "AWS::RDS::DBInstance"
  RDSDBInstance2:
    Properties:
      AvailabilityZone: eu-west-1b
      DBClusterIdentifier:
        Ref: RDSCluster
      DBInstanceClass: db.r3.xlarge
      DBParameterGroupName:
        Ref: RDSDBParameterGroup
      DBSubnetGroupName: DBSubnetGroup
      Engine: aurora
      PubliclyAccessible: "true"
    Type: "AWS::RDS::DBInstance"
  RDSDBParameterGroup:
    Type: 'AWS::RDS::DBParameterGroup'
    Properties:
      Description: CloudFormation Sample Aurora Parameter Group
      Family: aurora5.6
      Parameters:
        sql_mode: IGNORE_SPACE
        max_allowed_packet: 1024
        innodb_buffer_pool_size: '{DBInstanceClassMemory*3/4}'

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster",
  "Resources": {
    "RDSCluster": {
      "Properties": {
        "MasterUserPassword": "password",
        "MasterUsername": "username",
        "StorageEncrypted": false,
        "DBClusterParameterGroupName": {
          "Ref": "RDSDBClusterParameterGroup"
        },
        "DBSubnetGroupName": "DBSubnetGroup",
        "Engine": "aurora"
      },
      "Type": "AWS::RDS::DBCluster"
    },
    "RDSDBClusterParameterGroup": {
      "Properties": {
        "Description": "CloudFormation Sample Aurora Cluster Parameter Group",
        "Family": "aurora5.6",
        "Parameters": {
          "time_zone": "US/Eastern"
        }
      },
      "Type": "AWS::RDS::DBClusterParameterGroup"
    },
    "RDSDBInstance1": {
      "Properties": {
        "DBInstanceClass": "db.r3.xlarge",
        "DBParameterGroupName": {
          "Ref": "RDSDBParameterGroup"
        },
        "DBSubnetGroupName": "DBSubnetGroup",
        "Engine": "aurora",
        "PubliclyAccessible": "true",
        "AvailabilityZone": "eu-west-1b",
        "DBClusterIdentifier": {
          "Ref": "RDSCluster"
        }
      },
      "Type": "AWS::RDS::DBInstance"
    },
    "RDSDBInstance2": {
      "Properties": {
        "DBClusterIdentifier": {
          "Ref": "RDSCluster"
        },
        "DBInstanceClass": "db.r3.xlarge",
        "DBParameterGroupName": {
          "Ref": "RDSDBParameterGroup"
        },
        "DBSubnetGroupName": "DBSubnetGroup",
        "Engine": "aurora",
        "PubliclyAccessible": "true",
        "AvailabilityZone": "eu-west-1b"
      },
      "Type": "AWS::RDS::DBInstance"
    },
    "RDSDBParameterGroup": {
      "Type": "AWS::RDS::DBParameterGroup",
      "Properties": {
        "Description": "CloudFormation Sample Aurora Parameter Group",
        "Family": "aurora5.6",
        "Parameters": {
          "max_allowed_packet": 1024,
          "innodb_buffer_pool_size": "{DBInstanceClassMemory*3/4}",
          "sql_mode": "IGNORE_SPACE"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  NoEncryption:
    Type: 'AWS::RDS::DBCluster'
    Properties:
      MasterUsername: !Ref DBUsername
      MasterUserPassword: !Ref DBPassword
      DBClusterIdentifier: aurora-postgresql-cluster
      Engine: aurora-postgresql
      EngineVersion: '10.7'
      DBClusterParameterGroupName: default.aurora-postgresql10
      BackupRetentionPeriod: 7
      EnableCloudwatchLogsExports:
        - postgresql
  BackupRetention:
    Type: 'AWS::RDS::DBCluster'
    Properties:
      MasterUsername: !Ref DBUsername
      StorageEncrypted: true
      MasterUserPassword: !Ref DBPassword
      DBClusterIdentifier: aurora-postgresql-cluster
      Engine: aurora-postgresql
      EngineVersion: '10.7'
      DBClusterParameterGroupName: default.aurora-postgresql10
      EnableCloudwatchLogsExports:
        - postgresql

```