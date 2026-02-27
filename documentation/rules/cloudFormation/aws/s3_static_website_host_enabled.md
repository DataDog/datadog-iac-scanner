---
title: "S3 static website host enabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_static_website_host_enabled"
  id: "90501b1b-cded-4cc1-9e8b-206b85cda317"
  display_name: "S3 static website host enabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `90501b1b-cded-4cc1-9e8b-206b85cda317`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration.html)

### Description

S3 buckets configured for static website hosting expose content via the S3 website endpoint. These endpoints do not support HTTPS, and website hosting is frequently paired with public access. This increases the risk of accidental data exposure, content tampering, and man-in-the-middle attacks.

The `WebsiteConfiguration` property on `AWS::S3::Bucket` resources indicates static website hosting and must not be defined. This rule flags any resource where `Resources.<name>.Properties.WebsiteConfiguration` is present.

If you require public web content, serve it through a CDN (for example, CloudFront) and restrict bucket access via policies and PublicAccessBlock rather than enabling S3 website hosting. Ensure HTTPS is enforced at the CDN. Resources with `WebsiteConfiguration` defined will be flagged so you can remove the property or replace direct website hosting with a secured delivery approach.

Secure example (CloudFormation - no `WebsiteConfiguration` and public access blocked):

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    AccessControl: Private
    PublicAccessBlockConfiguration:
      BlockPublicAcls: true
      IgnorePublicAcls: true
      BlockPublicPolicy: true
      RestrictPublicBuckets: true
    BucketEncryption:
      ServerSideEncryptionConfiguration:
        - ServerSideEncryptionByDefault:
            SSEAlgorithm: AES256
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
    "Bucket2": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "AccessControl": "PublicRead",
        "WebsiteConfiguration": {
          "IndexDocument": "index.html",
          "ErrorDocument": "error.html"
        }
      }
    }
  }
}

```

```yaml
Resources:
  Bucket2:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
      WebsiteConfiguration:
        IndexDocument: index.html
        ErrorDocument: error.html

```