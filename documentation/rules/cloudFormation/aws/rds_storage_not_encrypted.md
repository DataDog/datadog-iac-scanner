---
title: "RDS storage not encrypted"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/rds_storage_not_encrypted"
  id: "5beacce3-4020-4a3d-9e1d-a36f953df630"
  display_name: "RDS storage not encrypted"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `5beacce3-4020-4a3d-9e1d-a36f953df630`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html)

### Description

RDS database instances must have storage encryption enabled to protect data at rest and to ensure snapshots and automated backups are encrypted. Without it, sensitive database contents can be exposed if storage media or backups are compromised. In AWS CloudFormation, the `AWS::RDS::DBInstance` resource must define the `StorageEncrypted` property and set it to `true`. Resources missing `StorageEncrypted` or with `StorageEncrypted` set to `false` will be flagged. Optionally set `KmsKeyId` to use a customer-managed KMS key when you require specific key control.

Secure configuration example:

```yaml
MyDBInstance:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceIdentifier: my-encrypted-db
    Engine: postgres
    EngineVersion: '14.7'
    DBInstanceClass: db.t3.micro
    AllocatedStorage: 20
    MasterUsername: admin
    MasterUserPassword: !Ref DBPassword
    StorageEncrypted: true
    KmsKeyId: !Ref MyKMSKey
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
  "Description": "RDS Storage Encrypted",
  "Parameters": {
    "SourceRegion": {
      "Type": "String"
    },
    "SourceDBInstanceIdentifier": {
      "Type": "String"
    },
    "DBInstanceType": {
      "Type": "String"
    }
  },
  "Resources": {
    "MyDBSmall": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "SourceDBInstanceIdentifier": "SourceDBInstanceIdentifier",
        "SourceRegion": "SourceRegion",
        "KmsKeyId": "MyKey",
        "StorageEncrypted": true,
        "DBInstanceClass": "DBInstanceType"
      }
    },
    "MyKey": {
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
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z"
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-11
Description: RDS Storage Encrypted2
Parameters:
  SourceDBInstanceIdentifier:
    Type: String
  DBInstanceType:
    Type: String
  SourceRegion:
    Type: String
Resources:
  MyKey2:
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
  MyDBSmall2:
    Type: "AWS::RDS::DBInstance"
    Properties:
      DBInstanceClass: !Ref DBInstanceType
      SourceDBInstanceIdentifier: !Ref SourceDBInstanceIdentifier
      SourceRegion: !Ref SourceRegion
      KmsKeyId: !Ref MyKey

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "RDS Storage Encrypted",
  "Parameters": {
    "SourceDBInstanceIdentifier": {
      "Type": "String"
    },
    "DBInstanceType": {
      "Type": "String"
    },
    "SourceRegion": {
      "Type": "String"
    }
  },
  "Resources": {
    "MyKey": {
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
    "MyDBSmall": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "DBInstanceClass": "DBInstanceType",
        "SourceDBInstanceIdentifier": "SourceDBInstanceIdentifier",
        "SourceRegion": "SourceRegion",
        "KmsKeyId": "MyKey",
        "StorageEncrypted": false
      }
    }
  }
}

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-11T00:00:00Z",
  "Description": "RDS Storage Encrypted2",
  "Parameters": {
    "SourceDBInstanceIdentifier": {
      "Type": "String"
    },
    "DBInstanceType": {
      "Type": "String"
    },
    "SourceRegion": {
      "Type": "String"
    }
  },
  "Resources": {
    "MyKey2": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
          "Statement": [
            {
              "Action": "kms:*",
              "Resource": "*",
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
              }
            }
          ],
          "Version": "2012-10-17T00:00:00Z",
          "Id": "key-default-1"
        }
      }
    },
    "MyDBSmall2": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "SourceRegion": "SourceRegion",
        "KmsKeyId": "MyKey",
        "DBInstanceClass": "DBInstanceType",
        "SourceDBInstanceIdentifier": "SourceDBInstanceIdentifier"
      }
    }
  }
}

```