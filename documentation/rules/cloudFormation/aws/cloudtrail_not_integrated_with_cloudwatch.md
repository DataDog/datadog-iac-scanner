---
title: "CloudTrail not integrated with CloudWatch"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudtrail_not_integrated_with_cloudwatch"
  id: "65d07da5-9af5-44df-8983-52d2e6f24c44"
  display_name: "CloudTrail not integrated with CloudWatch"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `65d07da5-9af5-44df-8983-52d2e6f24c44`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html)

### Description

 CloudTrail should be configured to deliver events to CloudWatch Logs so you have real-time monitoring, alerting, and a reliable audit trail for investigation and incident response. For `AWS::CloudTrail::Trail` resources, the `Properties` must include `CloudWatchLogsLogGroupArn` (the CloudWatch Log Group ARN) and `CloudWatchLogsRoleArn` (an IAM role ARN that CloudTrail can assume). Resources missing either property will be flagged. Ensure the referenced IAM role allows the CloudTrail service principal to write to CloudWatch Logs (for example, `logs:CreateLogStream` and `logs:PutLogEvents`).

Secure CloudFormation example:

```yaml
MyLogGroup:
  Type: AWS::Logs::LogGroup
  Properties:
    LogGroupName: /aws/cloudtrail/my-trail

MyTrailRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: cloudtrail.amazonaws.com
          Action: sts:AssumeRole
    Policies:
      - PolicyName: CloudTrailPutLogs
        PolicyDocument:
          Statement:
            - Effect: Allow
              Action:
                - logs:CreateLogStream
                - logs:PutLogEvents
              Resource: !GetAtt MyLogGroup.Arn

MyTrail:
  Type: AWS::CloudTrail::Trail
  Properties:
    IsLogging: true
    CloudWatchLogsLogGroupArn: !GetAtt MyLogGroup.Arn
    CloudWatchLogsRoleArn: !GetAtt MyTrailRole.Arn
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  OperatorEmail:
    Description: "Email address to notify when new logs are published."
    Type: String
Resources:
  S3Bucket:
    DeletionPolicy: Retain
    Type: AWS::S3::Bucket
    Properties: {}
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket:
        Ref: S3Bucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: "AWSCloudTrailAclCheck"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Action: "s3:GetBucketAcl"
            Resource: !Sub |-
              arn:aws:s3:::${S3Bucket}
          - Sid: "AWSCloudTrailWrite"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Action: "s3:PutObject"
            Resource: !Sub |-
              arn:aws:s3:::${S3Bucket}/AWSLogs/${AWS::AccountId}/*
            Condition:
              StringEquals:
                s3:x-amz-acl: "bucket-owner-full-control"
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Endpoint:
            Ref: OperatorEmail
          Protocol: email
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - Ref: "Topic"
      PolicyDocument:
        Version: "2008-10-17"
        Statement:
          - Sid: "AWSCloudTrailSNSPolicy"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Resource: "*"
            Action: "SNS:Publish"
  myTrail:
    DependsOn:
      - BucketPolicy
      - TopicPolicy
    Type: AWS::CloudTrail::Trail
    Properties:
      CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:920172477660:log-group:CloudTrail/DefaultLogGroup:*"
      CloudWatchLogsRoleArn:
        "Fn::GetAtt":
          - IamRoleForCwLogs
          - Arn
      S3BucketName:
        Ref: S3Bucket
      SnsTopicName:
        Fn::GetAtt:
          - Topic
          - TopicName
      IsLogging: true
      IsMultiRegionTrail: true
  IamRoleForCwLogs:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: ""
            Effect: Allow
            Principal:
              Service: cloudtrail.amazonaws.com
            Action: "sts:AssumeRole"
      Policies:
        - PolicyName: allow-access-to-cw-logs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - "logs:CreateLogStream"
                  - "logs:PutLogEvents"
                Resource: "*"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "OperatorEmail": {
      "Description": "Email address to notify when new logs are published.",
      "Type": "String"
    }
  },
  "Resources": {
    "S3Bucket": {
      "DeletionPolicy": "Retain",
      "Type": "AWS::S3::Bucket",
      "Properties": {}
    },
    "BucketPolicy": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {
          "Ref": "S3Bucket"
        },
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Sid": "AWSCloudTrailAclCheck",
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": "s3:GetBucketAcl",
              "Resource": "value"
            },
            {
              "Sid": "AWSCloudTrailWrite",
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": "s3:PutObject",
              "Resource": "value",
              "Condition": {
                "StringEquals": {
                  "s3:x-amz-acl": "bucket-owner-full-control"
                }
              }
            }
          ]
        }
      }
    },
    "Topic": {
      "Type": "AWS::SNS::Topic",
      "Properties": {
        "Subscription": [
          {
            "Endpoint": {
              "Ref": "OperatorEmail"
            },
            "Protocol": "email"
          }
        ]
      }
    },
    "TopicPolicy": {
      "Type": "AWS::SNS::TopicPolicy",
      "Properties": {
        "Topics": [
          {
            "Ref": "Topic"
          }
        ],
        "PolicyDocument": {
          "Version": "2008-10-17",
          "Statement": [
            {
              "Sid": "AWSCloudTrailSNSPolicy",
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Resource": "*",
              "Action": "SNS:Publish"
            }
          ]
        }
      }
    },
    "myTrail": {
      "DependsOn": [
        "BucketPolicy",
        "TopicPolicy"
      ],
      "Type": "AWS::CloudTrail::Trail",
      "Properties": {
        "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-west-2:920172477660:log-group:CloudTrail/DefaultLogGroup:*",
        "CloudWatchLogsRoleArn": {
          "Fn::GetAtt": [
            "IamRoleForCwLogs",
            "Arn"
          ]
        },
        "S3BucketName": {
          "Ref": "S3Bucket"
        },
        "SnsTopicName": {
          "Fn::GetAtt": [
            "Topic",
            "TopicName"
          ]
        },
        "IsLogging": true,
        "IsMultiRegionTrail": true
      }
    },
    "IamRoleForCwLogs": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Policies": [
          {
            "PolicyName": "allow-access-to-cw-logs",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                  ],
                  "Resource": "*"
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
Parameters:
  OperatorEmail:
    Description: "Email address to notify when new logs are published."
    Type: String
Resources:
  S3Bucket:
    DeletionPolicy: Retain
    Type: AWS::S3::Bucket
    Properties: {}
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket:
        Ref: S3Bucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: "AWSCloudTrailAclCheck"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Action: "s3:GetBucketAcl"
            Resource: !Sub |-
              arn:aws:s3:::${S3Bucket}
          - Sid: "AWSCloudTrailWrite"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Action: "s3:PutObject"
            Resource: !Sub |-
              arn:aws:s3:::${S3Bucket}/AWSLogs/${AWS::AccountId}/*
            Condition:
              StringEquals:
                s3:x-amz-acl: "bucket-owner-full-control"
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Endpoint:
            Ref: OperatorEmail
          Protocol: email
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - Ref: "Topic"
      PolicyDocument:
        Version: "2008-10-17"
        Statement:
          - Sid: "AWSCloudTrailSNSPolicy"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Resource: "*"
            Action: "SNS:Publish"
  myTrail2:
    DependsOn:
      - BucketPolicy
      - TopicPolicy
    Type: AWS::CloudTrail::Trail
    Properties:
      CloudWatchLogsRoleArn:
        "Fn::GetAtt":
          - IamRoleForCwLogs
          - Arn
      S3BucketName:
        Ref: S3Bucket
      SnsTopicName:
        Fn::GetAtt:
          - Topic
          - TopicName
      IsLogging: true
      IsMultiRegionTrail: true
  IamRoleForCwLogs:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: ""
            Effect: Allow
            Principal:
              Service: cloudtrail.amazonaws.com
            Action: "sts:AssumeRole"
      Policies:
        - PolicyName: allow-access-to-cw-logs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - "logs:CreateLogStream"
                  - "logs:PutLogEvents"
                Resource: "*"

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  OperatorEmail:
    Description: "Email address to notify when new logs are published."
    Type: String
Resources:
  S3Bucket:
    DeletionPolicy: Retain
    Type: AWS::S3::Bucket
    Properties: {}
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket:
        Ref: S3Bucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: "AWSCloudTrailAclCheck"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Action: "s3:GetBucketAcl"
            Resource: !Sub |-
              arn:aws:s3:::${S3Bucket}
          - Sid: "AWSCloudTrailWrite"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Action: "s3:PutObject"
            Resource: !Sub |-
              arn:aws:s3:::${S3Bucket}/AWSLogs/${AWS::AccountId}/*
            Condition:
              StringEquals:
                s3:x-amz-acl: "bucket-owner-full-control"
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Endpoint:
            Ref: OperatorEmail
          Protocol: email
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - Ref: "Topic"
      PolicyDocument:
        Version: "2008-10-17"
        Statement:
          - Sid: "AWSCloudTrailSNSPolicy"
            Effect: "Allow"
            Principal:
              Service: "cloudtrail.amazonaws.com"
            Resource: "*"
            Action: "SNS:Publish"
  myTrail3:
    DependsOn:
      - BucketPolicy
      - TopicPolicy
    Type: AWS::CloudTrail::Trail
    Properties:
      CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:920172477660:log-group:CloudTrail/DefaultLogGroup:*"
      S3BucketName:
        Ref: S3Bucket
      SnsTopicName:
        Fn::GetAtt:
          - Topic
          - TopicName
      IsLogging: true
      IsMultiRegionTrail: true
  IamRoleForCwLogs:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: ""
            Effect: Allow
            Principal:
              Service: cloudtrail.amazonaws.com
            Action: "sts:AssumeRole"
      Policies:
        - PolicyName: allow-access-to-cw-logs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - "logs:CreateLogStream"
                  - "logs:PutLogEvents"
                Resource: "*"

```

```json
{
  "Resources": {
    "S3Bucket": {
      "DeletionPolicy": "Retain",
      "Type": "AWS::S3::Bucket",
      "Properties": {}
    },
    "BucketPolicy": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {
          "Ref": "S3Bucket"
        },
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Sid": "AWSCloudTrailAclCheck",
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": "s3:GetBucketAcl",
              "Resource": "arn:aws:s3:::${S3Bucket}"
            },
            {
              "Sid": "AWSCloudTrailWrite",
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::${S3Bucket}/AWSLogs/${AWS::AccountId}/*",
              "Condition": {
                "StringEquals": {
                  "s3:x-amz-acl": "bucket-owner-full-control"
                }
              }
            }
          ]
        }
      }
    },
    "Topic": {
      "Type": "AWS::SNS::Topic",
      "Properties": {
        "Subscription": [
          {
            "Endpoint": {
              "Ref": "OperatorEmail"
            },
            "Protocol": "email"
          }
        ]
      }
    },
    "TopicPolicy": {
      "Type": "AWS::SNS::TopicPolicy",
      "Properties": {
        "Topics": [
          {
            "Ref": "Topic"
          }
        ],
        "PolicyDocument": {
          "Statement": [
            {
              "Sid": "AWSCloudTrailSNSPolicy",
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Resource": "*",
              "Action": "SNS:Publish"
            }
          ],
          "Version": "2008-10-17"
        }
      }
    },
    "myTrail": {
      "Properties": {
        "IsMultiRegionTrail": true,
        "CloudWatchLogsRoleArn": {
          "Fn::GetAtt": [
            "IamRoleForCwLogs",
            "Arn"
          ]
        },
        "S3BucketName": {
          "Ref": "S3Bucket"
        },
        "SnsTopicName": {
          "Fn::GetAtt": [
            "Topic",
            "TopicName"
          ]
        },
        "IsLogging": true
      },
      "DependsOn": [
        "BucketPolicy",
        "TopicPolicy"
      ],
      "Type": "AWS::CloudTrail::Trail"
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "OperatorEmail": {
      "Description": "Email address to notify when new logs are published.",
      "Type": "String"
    }
  }
}

```