---
title: "S3 bucket access to any principal"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_access_to_any_principal"
  id: "7772bb8c-c0f3-42d4-8e4e-f1b8939ad085"
  display_name: "S3 bucket access to any principal"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `7772bb8c-c0f3-42d4-8e4e-f1b8939ad085`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

Allowing any principal in an S3 bucket policy grants public (or universally authorized) access to the bucket. This can lead to data exposure, unintended read/write access, and unauthorized modifications. This rule checks `AWS::S3::Bucket` resources that have an associated `AWS::S3::BucketPolicy`. The rule flags bucket policies where `Properties.PolicyDocument.Statement` includes `Effect: "Allow"` and a wildcard principal (for example, `Principal: "*"`, or `Principal: { AWS: "*" }`). Bucket policy statements that explicitly list allowed principals (for example, an AWS account ARN or a specific IAM role) are acceptable. Statements with `Principal` as `*` (or equivalent) will be flagged as insecure.

Secure example with an explicit principal:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-bucket

MyBucketPolicy:
  Type: AWS::S3::BucketPolicy
  Properties:
    Bucket: !Ref MyBucket
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:root"
          Action: "s3:GetObject"
          Resource: !Sub "${MyBucket.Arn}/*"
```

## Compliant Code Examples
```yaml
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: false
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Bucket
      PolicyDocument:
        Statement:
        - Effect: Allow
          Principal:
            AWS:
            - arn:aws:iam::111122223333:user/Alice
            - arn:aws:iam::111122223333:user/foo
          Action: s3:GetObject
          Resource: arn:aws:s3:::DOC-EXAMPLE-BUCKET/*
          Condition:
            StringLike:
              'aws:Referer':
                - 'http://www.example.com/*'
                - 'http://example.net/*'
```

```json
{
  "Resources": {
    "Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": false,
          "BlockPublicPolicy": false,
          "IgnorePublicAcls": true,
          "RestrictPublicBuckets": true
        }
      }
    },
    "BucketPolicy": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "PolicyDocument": {
          "Statement": [
            {
              "Condition": {
                "StringLike": {
                  "aws:Referer": [
                    "http://www.example.com/*",
                    "http://example.net/*"
                  ]
                }
              },
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "arn:aws:iam::111122223333:user/Alice",
                  "arn:aws:iam::111122223333:user/foo"
                ]
              },
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"
            }
          ]
        },
        "Bucket": "Bucket"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": false,
          "BlockPublicPolicy": false,
          "IgnorePublicAcls": true,
          "RestrictPublicBuckets": false
        }
      }
    },
    "BucketPolicy": {
      "Properties": {
        "PolicyDocument": {
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "*"
                ]
              },
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*",
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
        "Bucket": "Bucket"
      },
      "Type": "AWS::S3::BucketPolicy"
    },
    "Bucket2": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": false,
          "BlockPublicPolicy": false,
          "IgnorePublicAcls": false,
          "RestrictPublicBuckets": true
        }
      }
    },
    "BucketPolicy2": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": "Bucket2",
        "PolicyDocument": {
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "*"
                ]
              },
              "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*",
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
        }
      }
    }
  }
}

```

```yaml
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: false
        IgnorePublicAcls: true
        RestrictPublicBuckets: false
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Bucket
      PolicyDocument:
        Statement:
        - Effect: Allow
          Principal:
            AWS:
            - "*"
          Action: s3:GetObject
          Resource: arn:aws:s3:::DOC-EXAMPLE-BUCKET/*
          Condition:
            StringLike:
              'aws:Referer':
                - 'http://www.example.com/*'
                - 'http://example.net/*'
  Bucket2:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: false
        IgnorePublicAcls: false
        RestrictPublicBuckets: true
  BucketPolicy2:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Bucket2
      PolicyDocument:
        Statement:
        - Effect: Allow
          Principal:
            AWS:
            - "*"
          Action: s3:GetObject
          Resource: arn:aws:s3:::DOC-EXAMPLE-BUCKET/*
          Condition:
            StringLike:
              'aws:Referer':
                - 'http://www.example.com/*'
                - 'http://example.net/*'
```