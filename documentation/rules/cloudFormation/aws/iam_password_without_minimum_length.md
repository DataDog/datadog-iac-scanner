---
title: "IAM password without minimum length"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_password_without_minimum_length"
  id: "b1b20ae3-8fa7-4af5-a74d-a2145920fcb1"
  display_name: "IAM password without minimum length"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `b1b20ae3-8fa7-4af5-a74d-a2145920fcb1`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-user)

### Description

 IAM user console passwords defined in AWS CloudFormation should be strong to reduce the risk of account compromise through brute force, credential stuffing, or simple credential reuse. For `AWS::IAM::User` resources, `Properties.LoginProfile.Password` must be a string with a minimum length of `14` characters. Passwords shorter than `14` characters will be flagged unless they reference a secret via an AWS Secrets Manager dynamic reference. Avoid embedding plaintext passwords in templates. Instead, reference secrets stored in AWS Secrets Manager or SSM Parameter Store, or rely on IAM-managed workflows and password policies. 
 
 Secure example with a sufficiently long password (or a secret reference) in CloudFormation:

```yaml
MyUser:
  Type: AWS::IAM::User
  Properties:
    UserName: example-user
    LoginProfile:
      Password: "S3cureP@ssw0rd2025"
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
        Password: myP@ssW0rd123asw
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
      - PolicyName: giveaccesstotopiconly
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - sns:*
            Resource:
            - !Ref mytopic
          - Effect: Deny
            Action:
            - sns:*
            NotResource:
            - !Ref mytopic
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
          "Password": "myP@ssW0rd123asw"
        },
        "Policies": [
          {
            "PolicyName": "giveaccesstoqueueonly",
            "PolicyDocument": {
              "Version": "2012-10-17",
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
              ]
            }
          },
          {
            "PolicyName": "giveaccesstotopiconly",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "sns:*"
                  ],
                  "Resource": [
                    "mytopic"
                  ]
                },
                {
                  "Action": [
                    "sns:*"
                  ],
                  "NotResource": [
                    "mytopic"
                  ],
                  "Effect": "Deny"
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
          },
          {
            "PolicyName": "giveaccesstotopiconly",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "sns:*"
                  ],
                  "Resource": [
                    "mytopic"
                  ]
                },
                {
                  "Effect": "Deny",
                  "Action": [
                    "sns:*"
                  ],
                  "NotResource": [
                    "mytopic"
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
      - PolicyName: giveaccesstotopiconly
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - sns:*
            Resource:
            - !Ref mytopic
          - Effect: Deny
            Action:
            - sns:*
            NotResource:
            - !Ref mytopic
```