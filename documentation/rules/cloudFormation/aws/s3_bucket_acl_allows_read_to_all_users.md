---
title: "S3 bucket ACL allows read to all users"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_acl_allows_read_to_all_users"
  id: "219f4c95-aa50-44e0-97de-cf71f4641170"
  display_name: "S3 bucket ACL allows read to all users"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `219f4c95-aa50-44e0-97de-cf71f4641170`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

 S3 buckets with a publicly readable ACL allow any internet user to list and download objects. This can lead to data leakage, accidental exposure of sensitive information, and compliance violations. This rule checks `AWS::S3::Bucket` resources and flags buckets whose `Properties.AccessControl` is set to `PublicRead`. To remediate, set `AccessControl` to `Private` or remove the ACL and enable S3 Block Public Access controls. If you must serve public content, use a CDN (CloudFront) with an origin access identity or a narrowly scoped bucket policy instead of a public ACL.

Secure CloudFormation example:

```yaml
MySecureBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-secure-bucket
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
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Creating S3 bucket",
  "Resources": {
    "JenkinsArtifacts05": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "AccessControl": "PublicReadWrite",
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
  }
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
        "AccessControl": "Private",
        "BucketName": "jenkins-secret-artifacts",
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
      AccessControl: PublicRead
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
      AccessControl: PublicRead
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
  "Resources": {
    "JenkinsArtifacts01": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "jenkins-artifacts",
        "Tags": [
          {
            "Key": "CostCenter",
            "Value": "ITEngineering"
          }
        ],
        "AccessControl": "PublicRead"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "Creating S3 bucket"
}

```