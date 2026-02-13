---
title: "KMS key rotation disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/kms_enable_key_rotation_disabled"
  id: "235ca980-eb71-48f4-9030-df0c371029eb"
  display_name: "KMS key rotation disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `235ca980-eb71-48f4-9030-df0c371029eb`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html)

### Description

KMS keys should have automatic key rotation enabled to limit the lifetime of cryptographic material, reduce the impact of a compromised key, and meet common compliance requirements. In AWS CloudFormation, `AWS::KMS::Key` resources must define the `EnableKeyRotation` property and set it to `true`. Resources missing this property or with `EnableKeyRotation` set to `false` will be flagged. Enabling rotation activates AWS-managed annual rotation of the key material.

Secure configuration example:

```yaml
MyKMSKey:
  Type: AWS::KMS::Key
  Properties:
    Description: KMS key with rotation enabled
    EnableKeyRotation: true
    KeyPolicy:
      Version: '2012-10-17'
      Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal:
            AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
          Action: 'kms:*'
          Resource: '*'
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
  myKey:
    Type: AWS::KMS::Key
    Properties:
      Description: An example symmetric CMK
      EnableKeyRotation: True
      KeyPolicy:
        Version: '2012-10-17'
        Id: key-default-1
        Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::111122223333:root
          Action: kms:*
          Resource: '*'
        - Sid: Allow administration of the key
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:user/Alice
          Action:
          - kms:Create*
          - kms:Describe*
          - kms:Enable*
          - kms:List*
          - kms:Put*
          - kms:Update*
          - kms:Revoke*
          - kms:Disable*
          - kms:Get*
          - kms:Delete*
          - kms:ScheduleKeyDeletion
          - kms:CancelKeyDeletion
          Resource: '*'
        - Sid: Allow use of the key
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:user/Bob
          Action:
          - kms:DescribeKey
          - kms:Encrypt
          - kms:Decrypt
          - kms:ReEncrypt*
          - kms:GenerateDataKey
          - kms:GenerateDataKeyWithoutPlaintext
          Resource: '*'
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "myKey": {
      "Properties": {
        "EnableKeyRotation": true,
        "KeyPolicy": {
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::111122223333:root"
              },
              "Action": "kms:*",
              "Resource": "*"
            },
            {
              "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
              ],
              "Resource": "*",
              "Sid": "Allow administration of the key",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/Alice"
              }
            },
            {
              "Sid": "Allow use of the key",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/Bob"
              },
              "Action": [
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyWithoutPlaintext"
              ],
              "Resource": "*"
            }
          ],
          "Version": "2012-10-17"
        },
        "Description": "An example symmetric CMK"
      },
      "Type": "AWS::KMS::Key"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "myKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::111122223333:root"
              },
              "Action": "kms:*",
              "Resource": "*"
            },
            {
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/Alice"
              },
              "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
              ],
              "Resource": "*",
              "Sid": "Allow administration of the key",
              "Effect": "Allow"
            },
            {
              "Sid": "Allow use of the key",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/Bob"
              },
              "Action": [
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyWithoutPlaintext"
              ],
              "Resource": "*"
            }
          ]
        },
        "Description": "An example symmetric CMK",
        "EnableKeyRotation": false
      }
    },
    "myKey2": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "An example symmetric CMK",
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::111122223333:root"
              },
              "Action": "kms:*",
              "Resource": "*"
            },
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/Alice"
              },
              "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
              ],
              "Resource": "*",
              "Sid": "Allow administration of the key"
            },
            {
              "Action": [
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyWithoutPlaintext"
              ],
              "Resource": "*",
              "Sid": "Allow use of the key",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/Bob"
              }
            }
          ]
        }
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
  myKey:
    Type: AWS::KMS::Key
    Properties:
      Description: An example symmetric CMK
      EnableKeyRotation: false
      KeyPolicy:
        Version: '2012-10-17'
        Id: key-default-1
        Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::111122223333:root
          Action: kms:*
          Resource: '*'
        - Sid: Allow administration of the key
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:user/Alice
          Action:
          - kms:Create*
          - kms:Describe*
          - kms:Enable*
          - kms:List*
          - kms:Put*
          - kms:Update*
          - kms:Revoke*
          - kms:Disable*
          - kms:Get*
          - kms:Delete*
          - kms:ScheduleKeyDeletion
          - kms:CancelKeyDeletion
          Resource: '*'
        - Sid: Allow use of the key
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:user/Bob
          Action:
          - kms:DescribeKey
          - kms:Encrypt
          - kms:Decrypt
          - kms:ReEncrypt*
          - kms:GenerateDataKey
          - kms:GenerateDataKeyWithoutPlaintext
          Resource: '*'
  myKey2:
    Type: AWS::KMS::Key
    Properties:
      Description: An example symmetric CMK
      KeyPolicy:
        Version: '2012-10-17'
        Id: key-default-1
        Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::111122223333:root
          Action: kms:*
          Resource: '*'
        - Sid: Allow administration of the key
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:user/Alice
          Action:
          - kms:Create*
          - kms:Describe*
          - kms:Enable*
          - kms:List*
          - kms:Put*
          - kms:Update*
          - kms:Revoke*
          - kms:Disable*
          - kms:Get*
          - kms:Delete*
          - kms:ScheduleKeyDeletion
          - kms:CancelKeyDeletion
          Resource: '*'
        - Sid: Allow use of the key
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:user/Bob
          Action:
          - kms:DescribeKey
          - kms:Encrypt
          - kms:Decrypt
          - kms:ReEncrypt*
          - kms:GenerateDataKey
          - kms:GenerateDataKeyWithoutPlaintext
          Resource: '*'
```