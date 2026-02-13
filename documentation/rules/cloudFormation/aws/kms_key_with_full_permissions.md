---
title: "KMS key with a vulnerable policy"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/kms_key_with_full_permissions"
  id: "da905474-7454-43c0-b8d2-5756ab951aba"
  display_name: "KMS key with a vulnerable policy"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `da905474-7454-43c0-b8d2-5756ab951aba`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-keypolicy)

### Description

 KMS keys must have a strict, explicit key policy because policies that grant broad `kms:*` permissions to wildcard principals (or omit a policy entirely) allow unintended principals to administer or use the key. This can lead to unauthorized decryption, key compromise, or deletion.

In AWS CloudFormation, inspect `AWS::KMS::Key` resources and verify `Properties.KeyPolicy.Statement[]`. A statement will be flagged when `Effect` is `Allow`, `Action` includes `kms:*`, and `Principal` is `*` (or contains wildcard values) without a restrictive `Condition`. Resources with `Properties.KeyPolicy` undefined or `null` are also flagged.

To remediate, define an explicit `KeyPolicy`, specify principals by ARN or AWS account ID, and limit `Action` to only the required KMS operations. If you must use `kms:*`, limit it to trusted administrative principals. You can also add conditions (for example, `aws:SourceAccount` or `aws:PrincipalOrgID`) to scope `Allow` statements.

Secure example with explicit principals and limited actions:

```yaml
MyKey:
  Type: AWS::KMS::Key
  Properties:
    KeyPolicy:
      Version: "2012-10-17"
      Statement:
        - Sid: AllowAppUse
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:role/MyAppRole
          Action:
            - "kms:Encrypt"
            - "kms:Decrypt"
          Resource: "*"
```


## Compliant Code Examples
```yaml
Resources:
  RSASigningKey:
    Type: AWS::KMS::Key
    Properties:
      Description: RSA-3047 asymmetric CMK for signing and verification
      KeySpec: RSA_3072
      KeyUsage: SIGN_VERIFY
      KeyPolicy:
        Version: '2012-10-17'
        Id: key-default-1
        Statement:
        - Sid: Allow use of the key
          Effect: Allow
          Principal:
            AWS: arn:aws:iam::111122223333:role/Developer
          Action:
          - kms:Sign
          - kms:Verify
          - kms:DescribeKey
          Resource: '*'

```

```json
{
  "Resources": {
    "RSASigningKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "RSA-3047 asymmetric CMK for signing and verification",
        "KeySpec": "RSA_3072",
        "KeyUsage": "SIGN_VERIFY",
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Allow administration of the key",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::111122223333:role/Admin"
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
            }
          ]
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Resources:
  RSASigningKey2:
    Type: AWS::KMS::Key
    Properties:
      Description: RSA-3047 asymmetric CMK for signing and verification
      KeySpec: RSA_3072
      KeyUsage: SIGN_VERIFY

```

```json
{
  "Resources": {
    "RSASigningKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "RSA-3047 asymmetric CMK for signing and verification",
        "KeySpec": "RSA_3072",
        "KeyUsage": "SIGN_VERIFY",
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-1",
          "Statement": [
            {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": "*"
              },
              "Action": "kms:*",
              "Resource": "*"
            }
          ]
        }
      }
    }
  }
}

```

```json
{
  "Resources": {
    "RSASigningKey2": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "RSA-3047 asymmetric CMK for signing and verification",
        "KeySpec": "RSA_3072",
        "KeyUsage": "SIGN_VERIFY"
      }
    }
  }
}

```