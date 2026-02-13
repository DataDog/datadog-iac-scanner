---
title: "IAM policies without groups"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_policies_without_groups"
  id: "5e7acff5-095b-40ac-9073-ac2e4ad8a512"
  display_name: "IAM policies without groups"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `5e7acff5-095b-40ac-9073-ac2e4ad8a512`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-policy)

### Description

Attaching IAM policies directly to individual users reduces centralized control and increases the risk of privilege sprawl, orphaned permissions, and inconsistent access management. This rule flags AWS CloudFormation `AWS::IAM::Policy` resources that define a non-empty `Properties.Policies[].Users` entry. Policies should be assigned to groups instead using the `Groups` property (or attached as managed policies to roles or groups) so permissions can be managed and audited centrally. Resources with `Resources.<name>.Properties.Policies[].Users` present and non-empty will be flagged. Replace user-level policy attachments with `Groups` (provide group names or `!Ref` to group resources) or use managed policy attachments for better lifecycle control.

Secure configuration example assigning the policy to a group:

```yaml
MyPolicy:
  Type: AWS::IAM::Policy
  Properties:
    PolicyName: AllowS3Read
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action:
            - "s3:GetObject"
          Resource: "*"
    Groups:
      - !Ref MyGroup
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
    myuser:
      Type: AWS::IAM::Policy
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
          Groups:
            - myexistinggroup1
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "myuser": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "Policies": [
          {
            "PolicyName": "giveaccesstoqueueonly",
            "PolicyDocument": {
              "Statement": [
                {
                  "Resource": [
                    "myqueue.Arn"
                  ],
                  "Effect": "Allow",
                  "Action": [
                    "sqs:*"
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
              ],
              "Version": "2012-10-17"
            },
            "Groups": [
              "myexistinggroup1"
            ]
          }
        ],
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
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "myuser": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "Path": "/",
        "LoginProfile": {
          "Password": "myP@ssW0rd"
        },
        "Policies": [
          {
            "PolicyName": "giveaccesstoqueueonly",
            "PolicyDocument": {
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
              ],
              "Version": "2012-10-17"
            },
            "Users": [
              "existinguser1",
              "existinguser2"
            ]
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
      Type: AWS::IAM::Policy
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
          Users:
            - existinguser1
            - existinguser2
```