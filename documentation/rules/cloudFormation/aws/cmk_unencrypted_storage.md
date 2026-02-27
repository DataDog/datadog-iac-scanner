---
title: "CMK unencrypted storage"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cmk_unencrypted_storage"
  id: "ffee2785-c347-451e-89f3-11aeb08e5c84"
  display_name: "CMK unencrypted storage"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `ffee2785-c347-451e-89f3-11aeb08e5c84`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html)

### Description

Storage encryption must be enabled for database and analytics clusters to protect data at rest and prevent exposure of sensitive data in volumes, snapshots, and backups if storage media or snapshots are compromised. In CloudFormation, the `StorageEncrypted` property must be defined and set to `true` for `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster`, `AWS::RDS::GlobalCluster`, `AWS::DocDB::DBCluster`, and `AWS::Neptune::DBCluster`. For `AWS::Redshift::Cluster`, the `Encrypted` property must be defined and set to `true`. Resources missing these properties or with the properties set to `false` will be flagged.

Secure configuration examples:

```yaml
MyRdsInstance:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceIdentifier: my-db
    StorageEncrypted: true
```

```yaml
MyRedshiftCluster:
  Type: AWS::Redshift::Cluster
  Properties:
    ClusterIdentifier: my-redshift
    Encrypted: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: RDS Storage Encrypted
Parameters:
  SourceDBInstanceIdentifier:
    Type: String
  DBInstanceType:
    Type: String
  SourceRegion:
    Type: String
Resources:
  MyKey:
    Type: "AWS::KMS::Key"
    Properties:
      KeyPolicy:
        Version: 2012-10-17
        Id: key-default-1
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Join
                - ""
                - - "arn:aws:iam::"
                  - !Ref "AWS::AccountId"
                  - ":root"
            Action: "kms:*"
            Resource: "*"
  MyDBSmall:
    Type: "AWS::RDS::DBInstance"
    Properties:
      DBInstanceClass: !Ref DBInstanceType
      SourceDBInstanceIdentifier: !Ref SourceDBInstanceIdentifier
      SourceRegion: !Ref SourceRegion
      KmsKeyId: !Ref MyKey
      StorageEncrypted: true


```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "AWS CloudFormation Sample Template",
  "Parameters": {
    "DBUsername": {
      "MaxLength": "16",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "must begin with a letter and contain only alphanumeric characters.",
      "NoEcho": "true",
      "Description": "Username for MySQL database access",
      "Type": "String",
      "MinLength": "1"
    },
    "DBPassword": {
      "Type": "String",
      "MinLength": "8",
      "MaxLength": "41",
      "AllowedPattern": "[a-zA-Z0-9]*",
      "ConstraintDescription": "must contain only alphanumeric characters.",
      "NoEcho": "true",
      "Description": "Password MySQL database access"
    }
  },
  "Resources": {
    "MyKey-0": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
          "Version": "2012-10-17T00:00:00Z",
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": ["", ["arn:aws:iam::", "AWS::AccountId", ":root"]]
              },
              "Action": "kms:*",
              "Resource": "*"
            }
          ]
        }
      }
    },
    "RDSCluster": {
      "Type": "AWS::RDS::DBCluster",
      "Properties": {
        "StorageEncrypted": true,
        "MasterUsername": "DBUsername",
        "DBClusterIdentifier": "my-serverless-cluster",
        "ScalingConfiguration": {
          "MinCapacity": 4,
          "MaxCapacity": 32,
          "SecondsUntilAutoPause": 1000,
          "AutoPause": true
        },
        "EngineMode": "serverless",
        "KmsKeyId": "MyKey-0",
        "MasterUserPassword": "DBPassword",
        "Engine": "aurora",
        "EngineVersion": "5.6.10a"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: >-
  AWS CloudFormation Sample Template
Parameters:
  DBUsername:
    NoEcho: 'true'
    Description: Username for MySQL database access
    Type: String
    MinLength: '1'
    MaxLength: '16'
    AllowedPattern: '[a-zA-Z][a-zA-Z0-9]*'
    ConstraintDescription: must begin with a letter and contain only alphanumeric characters.
  DBPassword:
    NoEcho: 'true'
    Description: Password MySQL database access
    Type: String
    MinLength: '8'
    MaxLength: '41'
    AllowedPattern: '[a-zA-Z0-9]*'
    ConstraintDescription: must contain only alphanumeric characters.
Resources:
  MyKey-0:
    Type: "AWS::KMS::Key"
    Properties:
      KeyPolicy:
        Version: 2012-10-17
        Id: key-default-1
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Join
                - ""
                - - "arn:aws:iam::"
                  - !Ref "AWS::AccountId"
                  - ":root"
            Action: "kms:*"
            Resource: "*"
  RDSCluster:
    Type: 'AWS::RDS::DBCluster'
    Properties:
      MasterUsername: !Ref DBUsername
      MasterUserPassword: !Ref DBPassword
      DBClusterIdentifier: my-serverless-cluster
      Engine: aurora
      EngineVersion: 5.6.10a
      EngineMode: serverless
      ScalingConfiguration:
        AutoPause: true
        MinCapacity: 4
        MaxCapacity: 32
        SecondsUntilAutoPause: 1000
      KmsKeyId: !Ref MyKey-0
      StorageEncrypted: true

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: >-
  AWS CloudFormation Sample Template
Parameters:
  DBUsername:
    NoEcho: "true"
    Description: Username for MySQL database access
    Type: String
    MinLength: "1"
    MaxLength: "16"
    AllowedPattern: "[a-zA-Z][a-zA-Z0-9]*"
    ConstraintDescription: must begin with a letter and contain only alphanumeric characters.
  DBPassword:
    NoEcho: "true"
    Description: Password MySQL database access
    Type: String
    MinLength: "8"
    MaxLength: "41"
    AllowedPattern: "[a-zA-Z0-9]*"
    ConstraintDescription: must contain only alphanumeric characters.
Resources:
  RDSCluster1:
    Type: "AWS::RDS::DBCluster"
    Properties:
      MasterUsername: !Ref DBUsername
      MasterUserPassword: !Ref DBPassword
      DBClusterIdentifier: my-serverless-cluster
      Engine: aurora
      EngineVersion: 5.6.10a
      EngineMode: serverless
      ScalingConfiguration:
        AutoPause: true
        MinCapacity: 4
        MaxCapacity: 32
        SecondsUntilAutoPause: 1000

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: >-
  AWS CloudFormation Sample Template AuroraServerlessDBCluster
Parameters:
  DBUsername:
    NoEcho: 'true'
    Description: Username for MySQL database access
    Type: String
    MinLength: '1'
    MaxLength: '16'
    AllowedPattern: '[a-zA-Z][a-zA-Z0-9]*'
    ConstraintDescription: must begin with a letter and contain only alphanumeric characters.
  DBPassword:
    NoEcho: 'true'
    Description: Password MySQL database access
    Type: String
    MinLength: '8'
    MaxLength: '41'
    AllowedPattern: '[a-zA-Z0-9]*'
    ConstraintDescription: must contain only alphanumeric characters.
Resources:
  RDSCluster-2:
    Type: 'AWS::RDS::DBCluster'
    Properties:
      MasterUsername: !Ref DBUsername
      MasterUserPassword: !Ref DBPassword
      DBClusterIdentifier: my-serverless-cluster
      Engine: aurora
      EngineVersion: 5.6.10a
      EngineMode: serverless
      ScalingConfiguration:
        AutoPause: true
        MinCapacity: 4
        MaxCapacity: 32
        SecondsUntilAutoPause: 1000
      StorageEncrypted: false

```

```json
{
  "Parameters": {
    "DBUsername": {
      "NoEcho": "true",
      "Description": "Username for MySQL database access",
      "Type": "String",
      "MinLength": "1",
      "MaxLength": "16",
      "AllowedPattern": "[a-zA-Z][a-zA-Z0-9]*",
      "ConstraintDescription": "must begin with a letter and contain only alphanumeric characters."
    },
    "DBPassword": {
      "Type": "String",
      "MinLength": "8",
      "MaxLength": "41",
      "AllowedPattern": "[a-zA-Z0-9]*",
      "ConstraintDescription": "must contain only alphanumeric characters.",
      "NoEcho": "true",
      "Description": "Password MySQL database access"
    }
  },
  "Resources": {
    "RDSCluster1": {
      "Type": "AWS::RDS::DBCluster",
      "Properties": {
        "DBClusterIdentifier": "my-serverless-cluster",
        "Engine": "aurora",
        "EngineVersion": "5.6.10a",
        "EngineMode": "serverless",
        "ScalingConfiguration": {
          "AutoPause": true,
          "MinCapacity": 4,
          "MaxCapacity": 32,
          "SecondsUntilAutoPause": 1000
        },
        "MasterUsername": "DBUsername",
        "MasterUserPassword": "DBPassword"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "AWS CloudFormation Sample Template"
}

```