---
title: "ECR repository is publicly accessible"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ecr_repository_is_publicly_accessible"
  id: "75be209d-1948-41f6-a8c8-e22dd0121134"
  display_name: "ECR repository is publicly accessible"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `75be209d-1948-41f6-a8c8-e22dd0121134`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html)

### Description

Amazon ECR repository policies that allow wildcard principals (`*`) grant public access to container images, enabling any AWS account or unauthenticated user to pull or push images. This increases the risk of data exposure, unauthorized deployments, and supply-chain compromise.
 
 The `RepositoryPolicyText` property of `AWS::ECR::Repository` resources must not contain `Statement` entries where `Effect` is `Allow` and the `Principal` includes `*`. This rule flags repository policy statements with `Principal` set to `*` and `Effect` set to `Allow`. Instead, specify explicit principals such as AWS account ARNs, IAM roles, or service principals and apply least-privilege actions and conditions.

Secure configuration example (restrict to a specific AWS account):

```yaml
MyRepository:
  Type: AWS::ECR::Repository
  Properties:
    RepositoryName: my-repo
    RepositoryPolicyText:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:root"
          Action:
            - "ecr:GetDownloadUrlForLayer"
            - "ecr:BatchGetImage"
            - "ecr:BatchCheckLayerAvailability"
          Resource: !Sub "arn:aws:ecr:${AWS::Region}:${AWS::AccountId}:repository/my-repo"
```

## Compliant Code Examples
```yaml
Resources:
  MyRepository1:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      RepositoryPolicyText:
        Version: "2012-10-17"
        Statement:
          -
            Sid: AllowPushPull
            Effect: Allow
            Principal:
              AWS:
                - "arn:aws:iam::123456789012:user/Bob"
                - "arn:aws:iam::123456789012:user/Alice"
            Action:
              - "ecr:GetDownloadUrlForLayer"
              - "ecr:BatchGetImage"
              - "ecr:BatchCheckLayerAvailability"
              - "ecr:PutImage"
              - "ecr:InitiateLayerUpload"
              - "ecr:UploadLayerPart"
              - "ecr:CompleteLayerUpload"

```

```json
{
  "Resources": {
    "MyRepository2": {
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
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "MyRepository4": {
      "Type": "AWS::ECR::Repository",
      "Properties": {
        "RepositoryName": "test-repository",
        "RepositoryPolicyText": {
          "Version": "2008-10-17",
          "Statement": [
            {
              "Sid": "AllowPushPull",
              "Effect": "Allow",
              "Principal": "*",
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

```yaml
Resources:
  MyRepository3:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      RepositoryPolicyText:
        Version: "2012-10-17"
        Statement:
          -
            Sid: AllowPushPull
            Effect: Allow
            Principal: "*"
            Action:
              - "ecr:GetDownloadUrlForLayer"
              - "ecr:BatchGetImage"
              - "ecr:BatchCheckLayerAvailability"
              - "ecr:PutImage"
              - "ecr:InitiateLayerUpload"
              - "ecr:UploadLayerPart"
              - "ecr:CompleteLayerUpload"

```