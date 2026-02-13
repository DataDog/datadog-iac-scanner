---
title: "RDS DB instance with deletion protection disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/rds_db_instance_with_deletion_protection_disabled"
  id: "2c161e58-cb52-454f-abea-6470c37b5e6e"
  display_name: "RDS DB instance with deletion protection disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Backup"
---
## Metadata

**Id:** `2c161e58-cb52-454f-abea-6470c37b5e6e`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-deletionprotection)

### Description

RDS DB instances must have deletion protection enabled to prevent accidental or unauthorized deletion that can cause irreversible data loss and service downtime. In AWS CloudFormation, the `DeletionProtection` property on `AWS::RDS::DBInstance` resources must be defined and set to `true`. Resources missing this property or with `DeletionProtection` set to `false` will be flagged. This does not replace regular snapshots or backups, so ensure backups are still configured.

Secure CloudFormation example:

```yaml
MyDBInstance:
  Type: AWS::RDS::DBInstance
  Properties:
    DBInstanceIdentifier: my-db
    Engine: mysql
    MasterUsername: admin
    MasterUserPassword: 'REPLACE_WITH_SECRET'
    DeletionProtection: true
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
      DeletionProtection: true
      KmsKeyId: !Ref MyKey
Outputs:
  InstanceId:
    Description: InstanceId of the newly created RDS Instance
    Value: !Ref MyDBSmall

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "RDS Storage Encrypted",
  "Parameters": {
    "DBInstanceType": {
      "Type": "String"
    },
    "SourceRegion": {
      "Type": "String"
    },
    "SourceDBInstanceIdentifier": {
      "Type": "String"
    }
  },
  "Resources": {
    "MyKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
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
          ],
          "Version": "2012-10-17T00:00:00Z"
        }
      }
    },
    "MyDBSmall": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "SourceDBInstanceIdentifier": "SourceDBInstanceIdentifier",
        "SourceRegion": "SourceRegion",
        "DeletionProtection": true,
        "KmsKeyId": "MyKey",
        "DBInstanceClass": "DBInstanceType"
      }
    }
  },
  "Outputs": {
    "InstanceId": {
      "Description": "InstanceId of the newly created RDS Instance",
      "Value": "MyDBSmall"
    }
  }
}

```
## Non-Compliant Code Examples
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
  MyKey1:
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
  MyDBSmall1:
    Type: "AWS::RDS::DBInstance"
    Properties:
      DBInstanceClass: !Ref DBInstanceType
      SourceDBInstanceIdentifier: !Ref SourceDBInstanceIdentifier
      SourceRegion: !Ref SourceRegion
      KmsKeyId: !Ref MyKey
Outputs:
  InstanceId:
    Description: InstanceId of the newly created RDS Instance
    Value: !Ref MyDBSmall1

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
              "Resource": "*",
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow"
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
        "DeletionProtection": false,
        "KmsKeyId": "MyKey"
      }
    }
  },
  "Outputs": {
    "InstanceId": {
      "Description": "InstanceId of the newly created RDS Instance",
      "Value": "MyDBSmall"
    }
  }
}

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
    "MyKey1": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
          "Id": "key-default-1",
          "Statement": [
            {
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
              "Resource": "*",
              "Sid": "Enable IAM User Permissions"
            }
          ],
          "Version": "2012-10-17T00:00:00Z"
        }
      }
    },
    "MyDBSmall1": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "SourceRegion": "SourceRegion",
        "KmsKeyId": "MyKey",
        "DBInstanceClass": "DBInstanceType",
        "SourceDBInstanceIdentifier": "SourceDBInstanceIdentifier"
      }
    }
  },
  "Outputs": {
    "InstanceId": {
      "Description": "InstanceId of the newly created RDS Instance",
      "Value": "MyDBSmall1"
    }
  }
}

```