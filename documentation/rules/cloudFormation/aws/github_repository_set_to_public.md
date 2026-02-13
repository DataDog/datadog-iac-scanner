---
title: "GitHub repository set to public"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/github_repository_set_to_public"
  id: "5906092d-5f74-490d-9a03-78febe0f65e1"
  display_name: "GitHub repository set to public"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `5906092d-5f74-490d-9a03-78febe0f65e1`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html)

### Description

 Public code repositories can expose source code, credentials, and intellectual property, increasing risk of data leakage and supply-chain compromise.
 
 In CloudFormation, `AWS::CodeStar::GitHubRepository` resources must include the `IsPrivate` property and set it to `true`. Resources that omit `IsPrivate` or have `IsPrivate` set to a non-`true` value will be flagged. 
 
 Secure configuration example:

```yaml
MyRepo:
  Type: AWS::CodeStar::GitHubRepository
  Properties:
    RepositoryName: my-repo
    IsPrivate: true
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyRepo1:
    Type: AWS::CodeStar::GitHubRepository
    Properties:
      Code:
        S3:
          Bucket: "my-bucket"
          Key: "sourcecode.zip"
          ObjectVersion: "1"
      EnableIssues: true
      IsPrivate: true
      RepositoryAccessToken: '{{resolve:secretsmanager:your-secret-manager-name:SecretString:your-secret-manager-key}}'
      RepositoryDescription: a description
      RepositoryName: my-github-repo
      RepositoryOwner: my-github-account

```

```json
{
  "Resources": {
    "MyRepo2": {
      "Type": "AWS::CodeStar::GitHubRepository",
      "Properties": {
        "Code": {
          "S3": {
            "Bucket": "my-bucket",
            "Key": "sourcecode.zip",
            "ObjectVersion": "1"
          }
        },
        "EnableIssues": true,
        "IsPrivate": true,
        "RepositoryAccessToken": "{{resolve:secretsmanager:your-secret-manager-name:SecretString:your-secret-manager-key}}",
        "RepositoryDescription": "a description",
        "RepositoryName": "my-github-repo",
        "RepositoryOwner": "my-github-account"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyRepo4:
    Type: AWS::CodeStar::GitHubRepository
    Properties:
      Code:
        S3:
          Bucket: "my-bucket"
          Key: "sourcecode.zip"
          ObjectVersion: "1"
      EnableIssues: true
      RepositoryAccessToken: '{{resolve:secretsmanager:your-secret-manager-name:SecretString:your-secret-manager-key}}'
      RepositoryDescription: a description
      RepositoryName: my-github-repo
      RepositoryOwner: my-github-account

```

```json
{
  "Resources": {
    "MyRepo5": {
      "Type": "AWS::CodeStar::GitHubRepository",
      "Properties": {
        "Code": {
          "S3": {
            "Bucket": "my-bucket",
            "Key": "sourcecode.zip",
            "ObjectVersion": "1"
          }
        },
        "EnableIssues": true,
        "RepositoryAccessToken": "{{resolve:secretsmanager:your-secret-manager-name:SecretString:your-secret-manager-key}}",
        "RepositoryDescription": "a description",
        "RepositoryName": "my-github-repo",
        "RepositoryOwner": "my-github-account"
      }
    }
  }
}

```

```json
{
  "Resources": {
    "MyRepo6": {
      "Type": "AWS::CodeStar::GitHubRepository",
      "Properties": {
        "Code": {
          "S3": {
            "Bucket": "my-bucket",
            "Key": "sourcecode.zip",
            "ObjectVersion": "1"
          }
        },
        "EnableIssues": true,
        "IsPrivate": false,
        "RepositoryAccessToken": "{{resolve:secretsmanager:your-secret-manager-name:SecretString:your-secret-manager-key}}",
        "RepositoryDescription": "a description",
        "RepositoryName": "my-github-repo",
        "RepositoryOwner": "my-github-account"
      }
    }
  }
}

```