---
title: "IAM managed policy applied to a user"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_managed_policy_applied_to_a_user"
  id: "0e5872b4-19a0-4165-8b2f-56d9e14b909f"
  display_name: "IAM managed policy applied to a user"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `0e5872b4-19a0-4165-8b2f-56d9e14b909f`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-groups)

### Description

 Attaching AWS managed IAM policies directly to individual users increases the risk of privilege sprawl and inconsistent permissions. It also makes auditing and centralized access control harder. Assigning policies to groups enforces consistent role-based access and simplifies permission management.
 
 In CloudFormation, validate `AWS::IAM::ManagedPolicy` resources: the `Users` property must not be populated (non-empty array). Instead, assign the managed policy via the `Groups` property (an array of group names or references) or attach the policy to `AWS::IAM::Group` resources. Resources with `Users` defined will be flagged. Remove `Users` and use `Groups` (or group attachments) to centrally manage access.

Secure CloudFormation example:

```yaml
MyManagedPolicy:
  Type: AWS::IAM::ManagedPolicy
  Properties:
    ManagedPolicyName: MyPolicy
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action: s3:ListBucket
          Resource: arn:aws:s3:::example-bucket
    Groups:
      - Ref: MyAdminGroup
```


## Compliant Code Examples
```yaml
Resources:
  CreateTestDBPolicy:
    Type: 'AWS::IAM::ManagedPolicy'
    Properties:
      Description: Policy for creating a test database
      Path: /
      PolicyDocument:
        Version: 2012-10-17
        Statement: []
      Groups:
        - TestGroup
```

```json
{
  "Resources": {
    "CreateTestDBPolicy": {
      "Type": "AWS::IAM::ManagedPolicy",
      "Properties": {
        "Path": "/",
        "PolicyDocument": {
          "Statement": [],
          "Version": "2012-10-17T00:00:00Z"
        },
        "Groups": [
          "TestGroup"
        ],
        "Description": "Policy for creating a test database"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "CreateTestDBPolicy": {
      "Type": "AWS::IAM::ManagedPolicy",
      "Properties": {
        "Path": "/",
        "PolicyDocument": {
          "Statement": [],
          "Version": "2012-10-17T00:00:00Z"
        },
        "Users": [
          "TestUser"
        ],
        "Description": "Policy for creating a test database"
      }
    }
  }
}

```

```yaml
Resources:
  CreateTestDBPolicy:
    Type: 'AWS::IAM::ManagedPolicy'
    Properties:
      Description: Policy for creating a test database
      Path: /
      PolicyDocument:
        Version: 2012-10-17
        Statement: []
      Users:
        - TestUser
```