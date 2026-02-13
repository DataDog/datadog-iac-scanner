---
title: "Default KMS key usage"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/default_kms_key_usage"
  id: "e52395b4-250b-4c60-81d5-2e58c1d37abc"
  display_name: "Default KMS key usage"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `e52395b4-250b-4c60-81d5-2e58c1d37abc`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html)

### Description

When storage encryption is enabled for database or analytics clusters or instances, explicitly specifying a customer-managed AWS KMS key prevents use of the AWS-managed default key. Using the AWS-managed default key can limit your ability to enforce key policies, control access, rotate keys, and audit key usage.

 In CloudFormation, this applies to `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster`, `AWS::DocDB::DBCluster`, `AWS::Neptune::DBCluster`, and `AWS::Redshift::Cluster`. `Properties.StorageEncrypted` must be `true`, and `Properties.KmsKeyId` must be defined and reference a customer-managed AWS KMS key (key ARN, alias, or a `Ref` to an `AWS::KMS::Key`). Resources with `StorageEncrypted` set to `true` and no `KmsKeyId` will be flagged.

 Define an `AWS::KMS::Key` and set `KmsKeyId` (for example, with `!Ref`) when you need explicit ownership, key policy control, or independent rotation and auditing.

Secure CloudFormation example:

```yaml
MyKmsKey:
  Type: AWS::KMS::Key
  Properties:
    Description: "CMK for DB encryption"

MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceIdentifier: my-db
    StorageEncrypted: true
    KmsKeyId: !Ref MyKmsKey
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
                "AWS": [
                  "",
                  [
                    "arn:aws:iam::",
                    "AWS::AccountId",
                    ":root"
                  ]
                ]
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
        "StorageEncrypted": true,
        "MasterUsername": "DBUsername",
        "MasterUserPassword": "DBPassword"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "AWS CloudFormation Sample Template"
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
  RDSCluster1:
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
      StorageEncrypted: true

```