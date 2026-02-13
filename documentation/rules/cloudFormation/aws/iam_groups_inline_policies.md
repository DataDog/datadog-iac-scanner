---
title: "IAM group inline policies"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_groups_inline_policies"
  id: "a58d1a2d-4078-4b80-855b-84cc3f7f4540"
  display_name: "IAM group inline policies"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `a58d1a2d-4078-4b80-855b-84cc3f7f4540`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html)

### Description

IAM groups should not contain inline policies because inline policies are tightly coupled to the group's lifecycle and are harder to audit, review, and reuse. This increases risk of accidental loss of permissions and inconsistent access control when groups are modified or deleted.
 
 In CloudFormation, check `AWS::IAM::Group` resources and ensure the `Properties.Policies` attribute is undefined or empty. Use reusable managed policies instead by specifying `ManagedPolicyArns` or creating `AWS::IAM::ManagedPolicy` resources and referencing them. Resources with a non-empty `Policies` list will be flagged as a security risk.

Secure configuration example (attach managed policies rather than inline policies):

```yaml
MyGroup:
  Type: AWS::IAM::Group
  Properties:
    GroupName: Devs
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/ReadOnlyAccess
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
    myuser:
      Type: AWS::IAM::Group
```

```json
{
  "Description": "A sample template",
  "Resources": {
    "myuser": {
      "Type": "AWS::IAM::Group"
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
    "myuser": {
      "Type": "AWS::IAM::Group",
      "Properties": {
        "Path": "/",
        "LoginProfile": {
          "Password": "myP@ssW0rd"
        },
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
                  "Effect": "Deny",
                  "Action": [
                    "sqs:*"
                  ],
                  "NotResource": [
                    "myqueue.Arn"
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
}

```

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
```