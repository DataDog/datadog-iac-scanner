---
title: "IAM user without password reset"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/user_iam_missing_password_reset_required"
  id: "a964d6e3-8e1e-4d93-8120-61fa640dd55a"
  display_name: "IAM user without password reset"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `a964d6e3-8e1e-4d93-8120-61fa640dd55a`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user-loginprofile.html)

### Description

 Console-enabled IAM users should require a password reset on first sign-in to prevent reuse of initial credentials if they are intercepted and to ensure each user sets a unique password.

In CloudFormation, check `AWS::IAM::User` resources. When `Properties.LoginProfile` contains a `Password`, `LoginProfile.PasswordResetRequired` must be present and set to `true`. This rule flags resources that omit `LoginProfile`, include only a `Password` without `PasswordResetRequired`, or explicitly set `PasswordResetRequired` to `false`.

Secure configuration example:

```yaml
MyUser:
  Type: AWS::IAM::User
  Properties:
    UserName: example-user
    LoginProfile:
      Password: "InitialPassword123!"
      PasswordResetRequired: true
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
         PasswordResetRequired: true
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
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "myuser": {
      "Type": "AWS::IAM::User",
      "Properties": {
        "Path": "/",
        "LoginProfile": {
          "Password": "myP@ssW0rd",
          "PasswordResetRequired": true
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
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
   newuser:
      Type: AWS::IAM::User
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

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
    topuser:
      Type: AWS::IAM::User
      Properties:
        Path: "/"
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
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "newuser": {
      "Type": "AWS::IAM::User",
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