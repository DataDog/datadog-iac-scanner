---
title: "IAM user LoginProfile password is in plaintext"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_user_login_profile_password_is_in_plaintext"
  id: "06adef8c-c284-4de7-aad2-af43b07a8ca1"
  display_name: "IAM user LoginProfile password is in plaintext"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `06adef8c-c284-4de7-aad2-af43b07a8ca1`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html)

### Description

Defining an IAM user's console password as a plaintext string in an AWS CloudFormation template embeds credentials in source control and template history, increasing the risk of credential leakage and unauthorized account access. For `AWS::IAM::User` resources, `Properties.LoginProfile.Password` must not be a string literal. Resources where `Properties.LoginProfile.Password` is a literal string will be flagged. Use an AWS Secrets Manager dynamic reference to supply the password so it is not stored directly in the template.

Secure configuration example using a Secrets Manager dynamic reference:

```yaml
MyUser:
  Type: AWS::IAM::User
  Properties:
    UserName: example-user
    LoginProfile:
      Password: "{{resolve:secretsmanager:my-app/iam/user-password:SecretString:password}}"
      PasswordResetRequired: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
    myTopuser:
      Type: AWS::IAM::User
      Properties:
        Path: "/"
        LoginProfile:
         Password:
         - !Ref NoEcho
         PasswordResetRequired: false
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

```json
{
  "Resources": {
    "myNewuser": {
      "Type": "AWS::IAM::User",
      "Properties": {
        "Path": "/",
        "LoginProfile": {
          "Password": [
            "secretsmanager"
          ],
          "PasswordResetRequired": false
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
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template"
}

```

```yaml

AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
    myNewuser:
      Type: AWS::IAM::User
      Properties:
        Path: "/"
        LoginProfile:
         Password:
         - !Ref secretsmanager
         PasswordResetRequired: false
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
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "myuser": {
      "Type": "AWS::IAM::User",
      "Properties": {
        "LoginProfile": {
          "Password": "myP@ssW0rd",
          "PasswordResetRequired": false
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
        ],
        "Path": "/"
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
      Type: AWS::IAM::User
      Properties:
        Path: "/"
        LoginProfile:
         Password: myP@ssW0rd
         PasswordResetRequired: false
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