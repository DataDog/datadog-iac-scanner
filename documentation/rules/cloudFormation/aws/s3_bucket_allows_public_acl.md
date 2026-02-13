---
title: "S3 bucket allows public ACL"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_allows_public_acl"
  id: "48f100d9-f499-4c6d-b2b8-deafe47ffb26"
  display_name: "S3 bucket allows public ACL"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `48f100d9-f499-4c6d-b2b8-deafe47ffb26`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html)

### Description

 S3 buckets should block public ACLs to prevent objects from being granted public access via ACLs. Public ACLs can lead to unintended data exposure. For `AWS::S3::Bucket` resources, `Properties.PublicAccessBlockConfiguration.BlockPublicAcls` must be set to `true`. Resources missing `PublicAccessBlockConfiguration`, or with `BlockPublicAcls: false`, will be flagged. Consider also enabling other `PublicAccessBlockConfiguration` flags (for example, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`) for broader protection.

Secure configuration example:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-bucket
    PublicAccessBlockConfiguration:
      BlockPublicAcls: true
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
          "IgnorePublicAcls": true,
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
        BlockPublicPolicy     : true
        IgnorePublicAcls      : true
        RestrictPublicBuckets : true
---
Resources:
  Bucket13:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy     : true
        IgnorePublicAcls      : true
        RestrictPublicBuckets : true                

```