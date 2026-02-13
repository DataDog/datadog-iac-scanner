---
title: "Unscanned ECR image"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/unscanned_ecr_image"
  id: "9025b2b3-e554-4842-ba87-db7aeec36d35"
  display_name: "Unscanned ECR image"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `9025b2b3-e554-4842-ba87-db7aeec36d35`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagescanningconfiguration)

### Description

ECR repositories should enable image scanning on push to detect known vulnerabilities before images are deployed. This reduces the risk of running vulnerable or compromised containers.

For `AWS::ECR::Repository` resources, `Properties.ImageScanningConfiguration.ScanOnPush` must be set to `true`. Resources missing `ImageScanningConfiguration`, or with `ScanOnPush` set to `false`, will be flagged.

To remediate, set `ImageScanningConfiguration.ScanOnPush` to `true` on the repository resource.

Secure configuration example:

```yaml
MyEcrRepository:
  Type: AWS::ECR::Repository
  Properties:
    RepositoryName: my-repo
    ImageScanningConfiguration:
      ScanOnPush: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-11"
Resources:
  MyRepository:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageScanningConfiguration:
        ScanOnPush: "true"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-11T00:00:00Z",
  "Resources": {
    "MyRepository2": {
      "Type": "AWS::ECR::Repository",
      "Properties": {
        "RepositoryName": "test-repository",
        "ImageScanningConfiguration": {
          "ScanOnPush": "true"
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-11"
Resources:
  MyRepository4:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageScanningConfiguration:
        ScanOnPush: "false"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "MyRepository5": {
      "Type": "AWS::ECR::Repository",
      "Properties": {
        "RepositoryName": "test-repository",
        "RepositoryPolicyText": {
          "Version": "2008-10-17",
          "Statement": [
            {
              "Sid": "AllowPushPull",
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "arn:aws:iam::123456789012:user/Bob",
                  "arn:aws:iam::123456789012:user/Alice"
                ]
              },
              "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload"
              ]
            }
          ]
        }
      }
    }
  }
}

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-11T00:00:00Z",
  "Resources": {
    "MyRepository6": {
      "Type": "AWS::ECR::Repository",
      "Properties": {
        "RepositoryName": "test-repository",
        "ImageScanningConfiguration": {
          "ScanOnPush": "false"
        }
      }
    }
  }
}

```