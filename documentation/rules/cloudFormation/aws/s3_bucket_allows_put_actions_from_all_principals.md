---
title: "S3 bucket allows put action from all principals"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_allows_put_actions_from_all_principals"
  id: "f6397a20-4cf1-4540-a997-1d363c25ef58"
  display_name: "S3 bucket allows put action from all principals"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `f6397a20-4cf1-4540-a997-1d363c25ef58`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

Bucket policies that allow S3 Put actions from the wildcard principal (`*`) enable anyone on the internet to upload or overwrite objects in the bucket. This can lead to unauthorized data tampering, malware uploads, or public exposure of sensitive content.

Check `AWS::S3::BucketPolicy` resources' `Properties.PolicyDocument.Statement` entries and flag statements where `Effect: "Allow"`, `Principal: "*"`, and `Action` includes Put operations such as `s3:PutObject` (or other `s3:Put*` actions). `Principal` should specify explicit principals (AWS account IDs, IAM role/user ARNs, or canonical user IDs). If `Principal` is `*`, the statement must include strict conditions (for example, `SourceIp` or `VpcEndpoint`) that effectively prevent public uploads. Statements with `Principal: "*"` and unrestrained Put actions will be flagged.

Secure configuration example allowing Put only to a specific role:

```yaml
MyBucketPolicy:
  Type: AWS::S3::BucketPolicy
  Properties:
    Bucket: !Ref MyBucket
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:role/UploadRole
          Action:
            - s3:PutObject
          Resource: arn:aws:s3:::my-bucket/*
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
  SampleBucketPolicy1:
    Type: 'AWS::S3::BucketPolicy'
    Properties:
      Bucket: !Ref DOC-EXAMPLE-BUCKET
      PolicyDocument:
        Statement:
          - Action:
              - 's3:PutObject'
            Effect: Deny
            Resource: '*'
            Principal: '*'
            Condition:
              StringLike:
                'aws:Referer':
                  - 'http://www.example.com/*'
                  - 'http://example.net/*'

```

```json
{
  "Resources": {
    "SampleBucketPolicy2": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {
          "Ref": "DOC-EXAMPLE-BUCKET"
        },
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "s3:PutObject"
              ],
              "Effect": "Deny",
              "Resource": "*",
              "Principal": "*",
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
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "SampleBucketPolicy5": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {
          "Ref": "DOC-EXAMPLE-BUCKET"
        },
        "PolicyDocument": {
          "Statement": [
            {
              "Action": "PutObject",
              "Effect": "Allow",
              "Resource": "*",
              "Principal": "*",
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
    },
    "SampleBucketPolicy6": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {
          "Ref": "DOC-EXAMPLE-BUCKET"
        },
        "PolicyDocument": {
          "Statement": [
            {
              "Action": [
                "PutObject",
                "GetObject"
              ],
              "Effect": "Allow",
              "Resource": "*",
              "Principal": "*",
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
#this is a problematic code where the query should report a result(s)
Resources:
  SampleBucketPolicy3:
    Type: 'AWS::S3::BucketPolicy'
    Properties:
      Bucket: !Ref DOC-EXAMPLE-BUCKET
      PolicyDocument:
        Statement:
          - Action: "PutObject"
            Effect: Allow
            Resource: "*"
            Principal: "*"
            Condition:
              StringLike:
                'aws:Referer':
                  - 'http://www.example.com/*'
                  - 'http://example.net/*'
  SampleBucketPolicy4:
    Type: 'AWS::S3::BucketPolicy'
    Properties:
      Bucket: !Ref DOC-EXAMPLE-BUCKET
      PolicyDocument:
        Statement:
          - Action:
              - "PutObject"
              - "GetObject"
            Effect: Allow
            Resource: "*"
            Principal: "*"
            Condition:
              StringLike:
                'aws:Referer':
                  - 'http://www.example.com/*'
                  - 'http://example.net/*'

```