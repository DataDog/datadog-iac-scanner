---
title: "KMS allows a wildcard principal"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/kms_allows_wildcard_principal"
  id: "f6049677-ec4a-43af-8779-5190b6d03cba"
  display_name: "KMS allows a wildcard principal"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `f6049677-ec4a-43af-8779-5190b6d03cba`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html)

### Description

KMS key policies that allow a wildcard principal (`*`) grant access to any AWS principal, including external or unauthenticated callers. This can enable unauthorized use of keys and lead to data decryption, key management abuse, or privilege escalation. In AWS CloudFormation, the `AWS::KMS::Key` resource's `Properties.KeyPolicy.Statement[]` must not have an `Effect: Allow` statement where `Principal` is `*` (or contains `*`). Specify explicit principals (AWS account IDs, IAM role or user ARNs, or service principals) and use conditions such as `aws:SourceAccount` or resource ARN restrictions to narrow access. Statements with `Effect: Allow` and `Principal: '*'` will be flagged.

Secure configuration example:

```yaml
MyKey:
  Type: AWS::KMS::Key
  Properties:
    KeyPolicy:
      Version: "2012-10-17"
      Statement:
        - Sid: AllowUseKey
          Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:role/MyRole"
          Action:
            - "kms:Encrypt"
            - "kms:Decrypt"
          Resource: "*"
          Condition:
            StringEquals:
              aws:SourceAccount: "123456789012"
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
              "Sid": "Allow administration of the key",
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
              "Resource": "*"
            },
            {
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
              "Resource": "*",
              "Sid": "Allow use of the key"
            }
          ]
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "myKey": {
      "Properties": {
        "Description": "An example symmetric CMK",
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Resource": "*",
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": "*",
              "Action": "kms:*"
            },
            {
              "Sid": "Allow administration of the key",
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
              "Resource": "*"
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
        }
      },
      "Type": "AWS::KMS::Key"
    }
  }
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
      KeyPolicy:
        Version: '2012-10-17'
        Id: key-default-1
        Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal: "*"
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