---
title: "Cross-account IAM assume role policy without external ID or MFA"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cross_account_iam_assume_role_policy_without_external_id_or_mfa"
  id: "85138beb-ce7c-4ca3-a09f-e8fbcc57ddd7"
  display_name: "Cross-account IAM assume role policy without external ID or MFA"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `85138beb-ce7c-4ca3-a09f-e8fbcc57ddd7`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-assumerolepolicydocument)

### Description

 Cross-account IAM role trust policies must require either an external ID or MFA to prevent confused-deputy attacks and reduce the risk of unauthorized cross-account access.

 Check `AWS::IAM::Role` resources' `AssumeRolePolicyDocument` for `Allow` statements that grant `sts:AssumeRole` to external AWS principals. Those statements must include a `Condition` requiring either the `sts:ExternalId` condition key (for example, `StringEquals`) or `aws:MultiFactorAuthPresent` set to `true`. Resources missing a `Condition` with `sts:ExternalId` or `aws:MultiFactorAuthPresent` will be flagged.

 Acceptable secure configurations include requiring an external ID or enforcing MFA in the trust policy, for example:

```yaml
MyRoleWithExternalId:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:root
          Action: sts:AssumeRole
          Condition:
            StringEquals:
              sts:ExternalId: my-external-id
```

```yaml
MyRoleWithMFA:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:root
          Action: sts:AssumeRole
          Condition:
            Bool:
              aws:MultiFactorAuthPresent: "true"
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
                  "AWS": "arn:aws:iam::987654321145:root"
                },
                "Effect": "Allow",
                "Resource": "*",
                "Sid": "",
                "Condition": {
                  "StringEquals": {
                    "sts:ExternalId": "98765"
                  }
                }
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
              "Action": "sts:AssumeRole",
              "Principal": {
                "AWS": "arn:aws:iam::987654321145:root"
              },
              "Effect": "Allow",
              "Resource": "*",
              "Sid": "",
              "Condition": { 
                "Bool": { 
                    "aws:MultiFactorAuthPresent": "true" 
                  }
              }
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
                  "AWS": "arn:aws:iam::987654321145:root"
                },
                "Effect": "Allow",
                "Resource": "*",
                "Sid": "",
                "Condition": { 
                  "Bool": { 
                      "aws:MultiFactorAuthPresent": "true" 
                    }
                }
              }
            ]
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
              "Action": "sts:AssumeRole",
              "Principal": {
                "AWS": "arn:aws:iam::987654321145:root"
              },
              "Effect": "Allow",
              "Resource": "*",
              "Sid": ""
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
          "Statement": {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "AWS": "arn:aws:iam::987654321145:root"
                },
                "Effect": "Allow",
                "Resource": "*",
                "Sid": "",
                "Condition": { 
                  "Bool": { 
                      "aws:MultiFactorAuthPresent": "false" 
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
          "Statement": {
              "Action": "sts:AssumeRole",
              "Principal": {
                "AWS": "arn:aws:iam::987654321145:root"
              },
              "Effect": "Allow",
              "Resource": "*",
              "Sid": "",
              "Condition": {
                "StringEquals": {
                  "sts:ExternalId": ""
                }
              }
          }
        }

```