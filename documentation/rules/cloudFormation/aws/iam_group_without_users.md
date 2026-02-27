---
title: "IAM group without users"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_group_without_users"
  id: "8f957abd-9703-413d-87d3-c578950a753c"
  display_name: "IAM group without users"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `8f957abd-9703-413d-87d3-c578950a753c`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html)

### Description

IAM groups should have at least one user assigned so that group permissions are actively used and auditable. Empty groups can hide orphaned or over-permissive permission sets and increase the risk of unintended access if the group is later reused.
 
 This rule checks CloudFormation templates and requires each `AWS::IAM::Group` to be referenced by at least one `AWS::IAM::User` via the user's `Groups` property. `AWS::IAM::Group` resources with no such references will be flagged.
 
 If group membership is managed outside CloudFormation (for example, by an external identity provider) or a group is intentionally created empty for future use, document that intent or manage membership through IaC to avoid false positives.

Secure example with a user assigned to the group:

```yaml
MyGroup:
  Type: AWS::IAM::Group
  Properties:
    GroupName: my-group

AliceUser:
  Type: AWS::IAM::User
  Properties:
    UserName: alice
    Groups:
      - !Ref MyGroup
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
    myuser:
      Type: AWS::IAM::Group
      Properties:
        Path: "/"
        LoginProfile:
          Password: myP@ssW0rd
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
    IamUserAdminSample:
      Type: AWS::IAM::User
      Condition: IsSampleIamUser
      Properties:
        UserName: sample-iam-user-admin
        Groups:
        - !Ref 'myuser'

```

```json
{
  "Description": "A sample template",
  "Resources": {
    "myuserr": {
      "Type": "AWS::IAM::Group",
      "Properties": {
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
        ],
        "Path": "/",
        "LoginProfile": {
          "Password": "myP@ssW0rd"
        }
      }
    },
    "IamUserAdminSample": {
      "Type": "AWS::IAM::User",
      "Condition": "IsSampleIamUser",
      "Properties": {
        "UserName": "sample-iam-user-admin",
        "Groups": [
          "myuserr"
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "myuseeer2": {
      "Type": "AWS::IAM::Group",
      "Properties": {
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
                  "Action": [
                    "sqs:*"
                  ],
                  "NotResource": [
                    "myqueue.Arn"
                  ],
                  "Effect": "Deny"
                }
              ]
            }
          }
        ],
        "Path": "/",
        "LoginProfile": {
          "Password": "myP@ssW0rd"
        }
      }
    },
    "IamUserAdminSample222": {
      "Type": "AWS::IAM::User",
      "Condition": "IsSampleIamUser",
      "Properties": {
        "UserName": "sample-iam-user-admin",
        "Groups": [
          "myu2ser"
        ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template 2
Resources:
    myuseeer:
      Type: AWS::IAM::Group
      Properties:
        Path: "/"
        LoginProfile:
          Password: myP@ssW0rd
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
    IamUserAdminSample22:
      Type: AWS::IAM::User
      Condition: IsSampleIamUser
      Properties:
        UserName: sample-iam-user-admin
        Groups:
        - !Ref 'myu2ser'

```