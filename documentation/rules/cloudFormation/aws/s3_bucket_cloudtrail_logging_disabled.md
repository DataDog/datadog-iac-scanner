---
title: "S3 bucket CloudTrail logging disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_cloudtrail_logging_disabled"
  id: "c3ce69fd-e3df-49c6-be78-1db3f802261c"
  display_name: "S3 bucket CloudTrail logging disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `c3ce69fd-e3df-49c6-be78-1db3f802261c`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-loggingconfig)

### Description

S3 buckets that receive CloudTrail log deliveries should have S3 server access logging enabled so access to log files and object-level operations are recorded for auditing and incident investigation. Without access logs, unauthorized reads, writes, or deletions of delivered logs may go undetected.

This rule looks for `AWS::S3::Bucket` resources referenced by an `AWS::S3::BucketPolicy` where `PolicyDocument.Statement[].Principal.Service == "cloudtrail.amazonaws.com"`. For those buckets, `Properties.LoggingConfiguration` must be defined. Resources missing `LoggingConfiguration` will be flagged. Set `LoggingConfiguration.DestinationBucketName` (and optionally `LogFilePrefix`) to a dedicated logging bucket to collect access logs.

Secure CloudFormation example:

```yaml
MyCloudTrailBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-cloudtrail-bucket
    LoggingConfiguration:
      DestinationBucketName: my-logging-bucket
      LogFilePrefix: access-logs/
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  mybucket:
    Type: "AWS::S3::Bucket"
    DeletionPolicy: Retain
    Properties:
      ReplicationConfiguration:
        Role:
          Fn::GetAtt:
            - WorkItemBucketBackupRole
            - Arn
        Rules:
          - Destination:
              Bucket:
                Fn::Join:
                  - ""
                  - - "arn:aws:s3:::"
                    - "Fn::Join":
                        - "-"
                        - - Ref: "AWS::Region"
                          - Ref: "AWS::StackName"
                          - replicationbucket
              StorageClass: STANDARD
            Id: Backup
            Prefix: ""
            Status: Enabled
      VersioningConfiguration:
        Status: Enabled
      LoggingConfiguration:
        DestinationBucketName: LoggingBucket
        LogFilePrefix: loga/
  WorkItemBucketBackupRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Action:
              - "sts:AssumeRole"
            Effect: Allow
            Principal:
              Service:
                - s3.amazonaws.com
  SampleBucketPolicy:
    Type: 'AWS::S3::BucketPolicy'
    Properties:
      Bucket:
        Ref: mybucket
      PolicyDocument:
        Statement:
          - Action:
              - 's3:GetObject'
            Effect: Allow
            Resource:
              'Fn::Join':
                - ''
                - - 'arn:aws:s3:::'
                  - Ref: DOC-EXAMPLE-BUCKET
                  - /*
            Principal:
              Service: 'cloudtrail.amazonaws.com'
            Condition:
              StringLike:
                'aws:Referer':
                  - 'http://www.example.com/*'
                  - 'http://example.net/*'

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "mybucket": {
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain",
      "Properties": {
        "ReplicationConfiguration": {
          "Role": {
            "Fn::GetAtt": [
              "WorkItemBucketBackupRole",
              "Arn"
            ]
          },
          "Rules": [
            {
              "Destination": {
                "Bucket": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:s3:::",
                      {
                        "Fn::Join": [
                          "-",
                          [
                            {
                              "Ref": "AWS::Region"
                            },
                            {
                              "Ref": "AWS::StackName"
                            },
                            "replicationbucket"
                          ]
                        ]
                      }
                    ]
                  ]
                },
                "StorageClass": "STANDARD"
              },
              "Id": "Backup",
              "Prefix": "",
              "Status": "Enabled"
            }
          ]
        },
        "VersioningConfiguration": {
          "Status": "Enabled"
        },
        "LoggingConfiguration": {
          "DestinationBucketName": "LoggingBucket",
          "LogFilePrefix": "loga/"
        }
      }
    },
    "WorkItemBucketBackupRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Statement": [
            {
              "Action": [
                "sts:AssumeRole"
              ],
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "s3.amazonaws.com"
                ]
              }
            }
          ]
        }
      }
    },
    "SampleBucketPolicy": {
      "Properties": {
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "s3:GetObject"
              ],
              "Effect": "Allow",
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "DOC-EXAMPLE-BUCKET"
                    },
                    "/*"
                  ]
                ]
              },
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              }
            }
          ]
        },
        "Bucket": {
          "Ref": "mybucket"
        }
      },
      "Type": "AWS::S3::BucketPolicy"
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
    "WorkItemBucketBackupRole": {
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Statement": [
            {
              "Action": [
                "sts:AssumeRole"
              ],
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "s3.amazonaws.com"
                ]
              }
            }
          ]
        }
      },
      "Type": "AWS::IAM::Role"
    },
    "sampleBucketPolicy": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {
          "Ref": "mybucketVulnerable"
        },
        "PolicyDocument": {
          "Statement": [
            {
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "DOC-EXAMPLE-BUCKET"
                    },
                    "/*"
                  ]
                ]
              },
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              },
              "Action": [
                "s3:GetObject"
              ],
              "Effect": "Allow"
            }
          ]
        }
      }
    },
    "mybucketVulnerable": {
      "Properties": {
        "ReplicationConfiguration": {
          "Role": {
            "Fn::GetAtt": [
              "WorkItemBucketBackupRole",
              "Arn"
            ]
          },
          "Rules": [
            {
              "Destination": {
                "Bucket": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:s3:::",
                      {
                        "Fn::Join": [
                          "-",
                          [
                            {
                              "Ref": "AWS::Region"
                            },
                            {
                              "Ref": "AWS::StackName"
                            },
                            "replicationbucket"
                          ]
                        ]
                      }
                    ]
                  ]
                },
                "StorageClass": "STANDARD"
              },
              "Id": "Backup",
              "Prefix": "",
              "Status": "Enabled"
            }
          ]
        },
        "VersioningConfiguration": {
          "Status": "Enabled"
        }
      },
      "Type": "AWS::S3::Bucket",
      "DeletionPolicy": "Retain"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  mybucketVulnerable:
    Type: "AWS::S3::Bucket"
    DeletionPolicy: Retain
    Properties:
      ReplicationConfiguration:
        Role:
          Fn::GetAtt:
            - WorkItemBucketBackupRole
            - Arn
        Rules:
          - Destination:
              Bucket:
                Fn::Join:
                  - ""
                  - - "arn:aws:s3:::"
                    - Fn::Join:
                        - "-"
                        - - Ref: "AWS::Region"
                          - Ref: "AWS::StackName"
                          - replicationbucket
              StorageClass: STANDARD
            Id: Backup
            Prefix: ""
            Status: Enabled
      VersioningConfiguration:
        Status: Enabled
  WorkItemBucketBackupRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Action:
              - "sts:AssumeRole"
            Effect: Allow
            Principal:
              Service:
                - s3.amazonaws.com
  sampleBucketPolicy:
    Type: 'AWS::S3::BucketPolicy'
    Properties:
      Bucket:
        Ref: mybucketVulnerable
      PolicyDocument:
        Statement:
          - Action:
              - 's3:GetObject'
            Effect: Allow
            Resource:
              Fn::Join:
                - ''
                - - 'arn:aws:s3:::'
                  - Ref: DOC-EXAMPLE-BUCKET
                  - /*
            Principal:
              Service: 'cloudtrail.amazonaws.com'
            Condition:
              StringLike:
                'aws:Referer':
                  - 'http://www.example.com/*'
                  - 'http://example.net/*'

```