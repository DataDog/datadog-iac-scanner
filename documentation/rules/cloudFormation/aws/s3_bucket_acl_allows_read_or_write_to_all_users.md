---
title: "S3 bucket ACL allows read or write to all users"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_acl_allows_read_or_write_to_all_users"
  id: "07dda8de-d90d-469e-9b37-1aca53526ced"
  display_name: "S3 bucket ACL allows read or write to all users"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `07dda8de-d90d-469e-9b37-1aca53526ced`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

S3 buckets must not use a public read-write ACL because it allows anyone on the internet to read, upload, modify, or delete objects. This risks data exposure, integrity loss, and service abuse. Check `AWS::S3::Bucket` resources and ensure the `AccessControl` property is not set to `PublicReadWrite`. Resources with `AccessControl: PublicReadWrite` will be flagged. Set `AccessControl` to `Private` or omit the ACL and enforce least-privilege access using bucket policies and a `PublicAccessBlockConfiguration` (enable `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`) to prevent accidental public access.

Secure configuration example:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-bucket
    AccessControl: Private
    PublicAccessBlockConfiguration:
      BlockPublicAcls: true
      IgnorePublicAcls: true
      BlockPublicPolicy: true
      RestrictPublicBuckets: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Creating S3 bucket
Resources:
  JenkinsArtifacts03:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: BucketOwnerFullControl
      BucketName: jenkins-artifacts
      VersioningConfiguration:
        Status: Enabled
      Tags:
        - Key: CostCenter
          Value: ITEngineering
        - Key: Type
          Value: CICD

```

```json
{
  "Resources": {
    "JenkinsArtifacts05": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "AccessControl": "PublicRead",
        "BucketName": "jenkins-secret-artifacts2",
        "VersioningConfiguration": {
          "Status": "Enabled"
        },
        "Tags": [
          {
            "Key": "CostCenter",
            "Value": "ITEngineering"
          }
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Creating S3 bucket"
}

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Creating S3 bucket",
  "Resources": {
    "JenkinsArtifacts04": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "Tags": [
          {
            "Key": "CostCenter",
            "Value": ""
          }
        ],
        "AccessControl": "Private",
        "BucketName": "jenkins-secret-artifacts",
        "VersioningConfiguration": {
          "Status": "Enabled"
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Creating S3 bucket
Resources:
  StaticPage01:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite
      BucketName: public-read-static-page01
      WebsiteConfiguration:
        ErrorDocument: 404.html
        IndexDocument: index.html
      Tags:
        - Key: CostCenter
          Value: ITEngineering

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Creating S3 bucket
Resources:
  JenkinsArtifacts02:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite
      BucketName: jenkins-artifacts-block-public
      PublicAccessBlockConfiguration:
        BlockPublicPolicy: false
      VersioningConfiguration:
        Status: Enabled
      Tags:
        - Key: CostCenter
          Value: ITEngineering
        - Key: Type
          Value: CICD

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Creating S3 bucket",
  "Resources": {
    "JenkinsArtifacts01": {
      "Properties": {
        "Tags": [
          {
            "Key": "CostCenter",
            "Value": "ITEngineering"
          }
        ],
        "AccessControl": "PublicReadWrite",
        "BucketName": "jenkins-artifacts"
      },
      "Type": "AWS::S3::Bucket"
    }
  }
}

```