---
title: "IAM policy on user"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_policy_on_user"
  id: "e4239438-e639-44aa-adb8-866e400e3ade"
  display_name: "IAM policy on user"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `e4239438-e639-44aa-adb8-866e400e3ade`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html)

### Description

IAM policies should be applied to groups rather than directly to individual users to centralize permission management and reduce privilege creep. This rule checks `AWS::IAM::Policy` resources and flags policies that define the `Users` property. Policies should instead use the `Groups` property (a list of group names or refs). Resources with `Properties.Users` present or without a `Groups` assignment will be flagged. Remove `Users` and attach the policy to one or more groups, then add users to those groups for consistent, auditable permission control.

Secure configuration example (CloudFormation YAML):

```yaml
MyPolicy:
  Type: AWS::IAM::Policy
  Properties:
    PolicyName: MyPolicy
    PolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Action: s3:ListBucket
          Resource: '*'
    Groups:
      - Ref: MyIamGroup
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
  GoodPolicy:
    Type: AWS::IAM::Policy
    Properties:
      Description: Policy for something.
      Path: "/"
      PolicyDocument:
        Version: '2012-10-17'
        Statement: []
      Groups:
      - user_group
```

```json
{
  "Resources": {
    "GoodPolicy": {
      "Properties": {
        "Description": "Policy for something.",
        "Path": "/",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": []
        },
        "Groups": [
          "user_group"
        ]
      },
      "Type": "AWS::IAM::Policy"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "BadPolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "Description": "Policy for something.",
        "Path": "/",
        "PolicyDocument": {
          "Statement": [],
          "Version": "2012-10-17"
        },
        "Users": [
          {
            "Ref": "TestUser"
          }
        ]
      }
    }
  }
}

```

```yaml
#this is a problematic code where the query should report a result(s)
Resources:
  BadPolicy:
    Type: AWS::IAM::Policy
    Properties:
      Description: Policy for something.
      Path: "/"
      PolicyDocument:
        Version: '2012-10-17'
        Statement: []
      Users:
      - Ref: TestUser
```