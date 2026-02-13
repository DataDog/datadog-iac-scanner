---
title: "IAM policy grants AssumeRole permission across all services"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_policy_grants_assumerole_permission_across_all_services"
  id: "e835bd0d-65da-49f7-b6d1-b646da8727e6"
  display_name: "IAM policy grants AssumeRole permission across all services"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `e835bd0d-65da-49f7-b6d1-b646da8727e6`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html)

### Description

 IAM policies must not grant the `sts:AssumeRole` action against all resources (`*`), because allowing AssumeRole on `*` enables principals to assume any role and can lead to privilege escalation and broad lateral movement. Check `AWS::IAM::Policy` resources' `Properties.PolicyDocument.Statement` entries for `Effect: Allow` with `Action` containing `sts:AssumeRole` (case-insensitive) and `Resource` equal to `*` or containing `*`. Statements that allow `sts:AssumeRole` must instead restrict `Resource` to explicit role ARNs or a limited set of ARNs (for example, `arn:aws:iam::123456789012:role/MyRole`). Resources missing this restriction or with `Resource: "*"` will be flagged.

Secure configuration example (restrict the resource to a specific role ARN):

```yaml
MyPolicy:
  Type: AWS::IAM::Policy
  Properties:
    PolicyName: RestrictAssumeRole
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action: sts:AssumeRole
          Resource: arn:aws:iam::123456789012:role/SpecificRole
    Roles:
      - Ref: SomeRole
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: mygrouppolicy
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
              - s3:PutObject
              - s3:PutObjectAcl
            Resource: arn:aws:s3:::myAWSBucket/*
      Groups:
        - myexistinggroup1
        - !Ref mygroup

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "MyPolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "mygrouppolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:PutObjectAcl"
              ],
              "Resource": "arn:aws:s3:::myAWSBucket/*"
            }
          ]
        },
        "Groups": [
          "myexistinggroup1",
          "mygroup"
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Description": "A sample template",
  "Resources": {
    "mypolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "mygrouppolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "sts:AssumeRole"
              ],
              "Resource": "*"
            }
          ]
        },
        "Users": [
          "SomeUser"
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  mypolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: mygrouppolicy
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Action: ["sts:AssumeRole"]
          Resource: "*"
      Users: ["SomeUser"]

```