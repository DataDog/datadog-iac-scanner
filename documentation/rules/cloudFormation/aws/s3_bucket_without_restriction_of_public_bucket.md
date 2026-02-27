---
title: "S3 bucket without restriction of public bucket"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_without_restriction_of_public_bucket"
  id: "350cd468-0e2c-44ef-9d22-cfb73a62523c"
  display_name: "S3 bucket without restriction of public bucket"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `350cd468-0e2c-44ef-9d22-cfb73a62523c`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html)

### Description

S3 buckets should restrict public bucket settings to prevent accidental or unauthorized public exposure of objects. This also ensures bucket-level public access controls are enforced.

In CloudFormation, `AWS::S3::Bucket` resources must define `Properties.PublicAccessBlockConfiguration.RestrictPublicBuckets` and set it to `true`. Resources missing `PublicAccessBlockConfiguration`, missing `RestrictPublicBuckets`, or with `RestrictPublicBuckets: false` will be flagged.

Secure configuration example:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-bucket
    PublicAccessBlockConfiguration:
      BlockPublicAcls: true
      BlockPublicPolicy: true
      IgnorePublicAcls: true
      RestrictPublicBuckets: true
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
          "BlockPublicPolicy": true,
          "IgnorePublicAcls": false,
          "RestrictPublicBuckets": false
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
        BlockPublicPolicy     : true
---
Resources:
  Bucket13:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy     : true
        IgnorePublicAcls      : false
        RestrictPublicBuckets : false                

```