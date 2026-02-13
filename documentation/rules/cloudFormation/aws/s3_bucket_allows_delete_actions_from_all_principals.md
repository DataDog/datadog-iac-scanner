---
title: "S3 bucket allows delete action from all principals"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_allows_delete_actions_from_all_principals"
  id: "acc78859-765e-4011-a229-a65ea57db252"
  display_name: "S3 bucket allows delete action from all principals"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `acc78859-765e-4011-a229-a65ea57db252`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

 S3 bucket policies must not allow delete actions to all principals (`*`). Public delete permissions enable unauthorized users to remove or tamper with objects and buckets, causing data loss and service disruption. Check `AWS::S3::BucketPolicy` resources' `Properties.PolicyDocument.Statement` entries. Ensure no statement has `Effect: "Allow"` with `Principal` equal to `*` (or an array containing `*`) while `Action` includes delete operations such as `s3:DeleteObject`, `s3:DeleteBucket`, `s3:DeleteObjectVersion`, or wildcard actions that grant delete privileges.

Statements that combine `Effect: "Allow"`, `Principal: "*"`, and any delete action will be flagged. Instead, restrict delete permissions to explicit principals (account IDs, ARNs, or specific service principals) or remove `Allow` for delete actions to public principals. `Action` may be a single string or a list. Both forms are checked.

Secure example restricting delete to a specific AWS account:

```yaml
MyBucketPolicy:
  Type: AWS::S3::BucketPolicy
  Properties:
    Bucket: my-bucket
    PolicyDocument:
      Statement:
        - Sid: AllowSpecificAccountDeletes
          Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:root"
          Action:
            - "s3:DeleteObject"
            - "s3:DeleteObjectVersion"
          Resource: "arn:aws:s3:::my-bucket/*"
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
              - 's3:DeleteObject'
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
                "s3:DeleteObject"
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
              "Action": "DeleteObject",
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
                "DeleteObject",
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
          - Action: "DeleteObject"
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
              - "DeleteObject"
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