---
title: "S3 bucket allows public policy"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_with_public_policy"
  id: "860ba89b-b8de-4e72-af54-d6aee4138a69"
  display_name: "S3 bucket allows public policy"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `860ba89b-b8de-4e72-af54-d6aee4138a69`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html)

### Description

 S3 buckets should block public bucket policies to prevent bucket policies from granting public access. Public bucket policies can expose objects or other sensitive data.

For `AWS::S3::Bucket` resources, `Properties.PublicAccessBlockConfiguration.BlockPublicPolicy` must be set to `true`. Resources missing `PublicAccessBlockConfiguration`, or with `BlockPublicPolicy: false`, will be flagged.

Secure configuration example:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    PublicAccessBlockConfiguration:
      BlockPublicPolicy: true
```


## Compliant Code Examples
```yaml
Resources:
  Bucket1:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls       : true
        BlockPublicPolicy     : true
        IgnorePublicAcls      : true
        RestrictPublicBuckets : true
```

```json
{
  "Resources": {
    "Bucket1": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": true,
          "BlockPublicPolicy": true,
          "IgnorePublicAcls": true,
          "RestrictPublicBuckets": true
        },
        "AccessControl": "Private"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "Bucket1": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": false,
          "BlockPublicPolicy": false,
          "IgnorePublicAcls": false,
          "RestrictPublicBuckets": true
        },
        "AccessControl": "Private"
      }
    }
  }
}

```

```yaml
Resources:
  Bucket11:
    Type: AWS::S3::Bucket
    Properties:
---
Resources:
  Bucket12:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        RestrictPublicBuckets : true
---
Resources:
  Bucket13:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy     : false
        IgnorePublicAcls      : false
        RestrictPublicBuckets : true                

```