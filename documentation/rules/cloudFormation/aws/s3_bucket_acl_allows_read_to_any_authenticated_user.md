---
title: "S3 bucket ACL allows read to any authenticated user"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_acl_allows_read_to_any_authenticated_user"
  id: "835d5497-a526-4aea-a23f-98a9afd1635f"
  display_name: "S3 bucket ACL allows read to any authenticated user"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `835d5497-a526-4aea-a23f-98a9afd1635f`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

S3 buckets configured with the `AuthenticatedRead` canned ACL allow any AWS authenticated user to read bucket objects. This can lead to unintended data exposure and compliance violations. For CloudFormation, the `AWS::S3::Bucket` resource's `AccessControl` property must not be set to `AuthenticatedRead`. Resources with `AccessControl: AuthenticatedRead` will be flagged. Set `AccessControl: Private` or omit ACLs and enforce least-privilege access using explicit bucket policies or IAM principals instead.

Secure configuration example:

```yaml
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: my-bucket
    AccessControl: Private
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
      "Properties": {
        "BucketName": "jenkins-secret-artifacts2",
        "VersioningConfiguration": {
          "Status": "Enabled"
        },
        "Tags": [
          {
            "Value": "ITEngineering",
            "Key": "CostCenter"
          }
        ],
        "AccessControl": "PublicReadWrite"
      },
      "Type": "AWS::S3::Bucket"
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
            "Value": ""
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
      AccessControl: AuthenticatedRead
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
      AccessControl: AuthenticatedRead
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
        "AccessControl": "AuthenticatedRead",
        "BucketName": "jenkins-artifacts",
        "Tags": [
          {
            "Value": "ITEngineering",
            "Key": "CostCenter"
          }
        ]
      },
      "Type": "AWS::S3::Bucket"
    }
  }
}

```