---
title: "IAM policies attached to a user"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_policies_attached_to_user"
  id: "edc95c10-7366-4f30-9b4b-f995c84eceb5"
  display_name: "IAM policies attached to a user"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `edc95c10-7366-4f30-9b4b-f995c84eceb5`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)

### Description

Directly attaching IAM policies to individual users increases management complexity and raises the risk of privilege sprawl and inconsistent access control. Centralizing permissions onto groups or roles makes audits and least-privilege enforcement easier. This rule checks AWS CloudFormation `AWS::IAM::User` resources and requires that `Properties.Policies` (inline policies) and `Properties.ManagedPolicyArns` (managed policy ARNs) are undefined or empty. Resources that define non-empty `Policies` or `ManagedPolicyArns` will be flagged; instead attach managed or inline policies to `AWS::IAM::Group` or `AWS::IAM::Role` and assign users to those groups or have them assume roles to receive permissions.

Secure configuration example (attach policies to a group and add the user to the group):

```yaml
MyUserGroup:
  Type: AWS::IAM::Group
  Properties:
    GroupName: my-group
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/ReadOnlyAccess

MyUser:
  Type: AWS::IAM::User
  Properties:
    UserName: my-user
    Groups:
      - !Ref MyUserGroup
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
    myuser:
      Type: AWS::IAM::User
      Properties:
        Path: "/"
        LoginProfile:
          Password: myP@ssW0rd
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "myuser": {
      "Type": "AWS::IAM::User",
      "Properties": {
        "Path": "/",
        "LoginProfile": {
          "Password": "myP@ssW0rd"
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "myuser": {
      "Type": "AWS::IAM::User",
      "Properties": {
        "Path": "/",
        "LoginProfile": {
          "Password": "myP@ssW0rd"
        },
        "ManagedPoliciesArns": [
          "arn:aws:iam::123456789012:policy/UsersManageOwnCredentials",
          "arn:aws:iam::123456789012:policy/division_abc/subdivision_xyz/UsersManageOwnCredentials"
        ],
        "Policies": [
          {
            "PolicyName": "giveaccesstoqueueonly",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "sqs:*"
                  ],
                  "Resource": [
                    "myqueue.Arn"
                  ]
                },
                {
                  "NotResource": [
                    "myqueue.Arn"
                  ],
                  "Effect": "Deny",
                  "Action": [
                    "sqs:*"
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template"
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
    myuser:
      Type: AWS::IAM::User
      Properties:
        Path: "/"
        LoginProfile:
          Password: myP@ssW0rd
        ManagedPoliciesArns: [
          "arn:aws:iam::123456789012:policy/UsersManageOwnCredentials",
          "arn:aws:iam::123456789012:policy/division_abc/subdivision_xyz/UsersManageOwnCredentials"
        ]
        Policies:
        - PolicyName: giveaccesstoqueueonly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
            - Effect: Allow
              Action:
              - sqs:*
              Resource:
              - !GetAtt myqueue.Arn
            - Effect: Deny
              Action:
              - sqs:*
              NotResource:
              - !GetAtt myqueue.Arn
```