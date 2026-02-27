---
title: "IAM role allows all principals to assume"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_role_allows_all_principals_to_assume"
  id: "f80e3aa7-7b34-4185-954e-440a6894dde6"
  display_name: "IAM role allows all principals to assume"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `f80e3aa7-7b34-4185-954e-440a6894dde6`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-assumerolepolicydocument)

### Description

IAM role trust policies must not grant account-root or wildcard principals permission to assume the role, because allowing principals like an account root ARN (`arn:aws:iam::123456789012:root`) or `*` effectively trusts every principal in an account or every AWS account and can enable privilege escalation or unintended cross-account access. Check `AWS::IAM::Role` resources' `Properties.AssumeRolePolicyDocument.Statement[].Principal.AWS`. The principal value must not be `*` or contain `:root`. Only statements with `Effect: Allow` are evaluated. Resources with `Principal.AWS` containing `:root` or `*` will be flagged and should be replaced with explicit principal ARNs or specific service principals.

Secure example with an explicit principal ARN:

```yaml
MyRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:role/TrustedRole
          Action: sts:AssumeRole
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  RootRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument: >
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {
                        "AWS": "arn:aws:iam::root"
                    },
                    "Effect": "Deny",
                    "Sid": ""
                }
            ]
        }

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "RootRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Deny",
              "Principal": {
                "AWS": [
                  "arn:aws:iam::root"
                ]
              },
              "Action": [
                "sts:AssumeRole"
              ]
            }
          ]
        },
        "Path": "/"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "RootRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "arn:aws:iam::root"
                ]
              },
              "Action": [
                "sts:AssumeRole"
              ]
            }
          ]
        },
        "Path": "/"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  RootRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument: >
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {
                        "AWS": "arn:aws:iam::root"
                    },
                    "Effect": "Allow",
                    "Sid": ""
                }
            ]
        }

```