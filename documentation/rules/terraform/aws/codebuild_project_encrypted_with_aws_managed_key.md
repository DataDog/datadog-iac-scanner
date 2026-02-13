---
title: "CodeBuild project encrypted with AWS managed key"
group_id: "Terraform / AWS"
meta:
  name: "aws/codebuild_project_encrypted_with_aws_managed_key"
  id: "3deec14b-03d2-4d27-9670-7d79322e3340"
  display_name: "CodeBuild project encrypted with AWS managed key"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Encryption"
---
## Metadata

**Id:** `3deec14b-03d2-4d27-9670-7d79322e3340`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_key)

### Description

 This check ensures that AWS CodeBuild projects are encrypted using customer-managed KMS keys rather than the default AWS-managed keys. Using the default AWS-managed key (for example, `encryption_key = data.aws_kms_key.by_alias.arn` with `key_id = "alias/aws/s3"`) limits your control over key rotation, access policies, and audit logging, potentially increasing the risk of unauthorized data access. To maximize security and compliance, the `encryption_key` attribute should reference a customer-managed KMS key (such as `key_id = "alias/myAlias"`), allowing organizations to fully manage encryption controls for sensitive CodeBuild project data.


## Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

data "aws_kms_key" "by_alias2" {
  key_id = "alias/myAlias"
}

# No policy attached to this role because it is for testing purposes
resource "aws_iam_role" "codebuild2" {
  name = "codebuild-cloudrail-test"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_codebuild_project" "project-cloudrail-test2" {
  name           = "project-cloudrail-test"
  description    = "project-cloudrail-test"
  build_timeout  = "5"
  queued_timeout = "5"
  service_role   = aws_iam_role.codebuild2.arn
  encryption_key = data.aws_kms_key.by_alias2.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  cache {
    type  = "LOCAL"
    modes = ["LOCAL_DOCKER_LAYER_CACHE", "LOCAL_SOURCE_CACHE"]
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:1.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "SOME_KEY1"
      value = "SOME_VALUE1"
    }
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/foo/bar.git"
    git_clone_depth = 1
  }
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

data "aws_kms_key" "by_alias" {
  key_id = "alias/aws/s3"
}

# No policy attached to this role because it is for testing purposes
resource "aws_iam_role" "codebuild" {
  name = "codebuild-cloudrail-test"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_codebuild_project" "project-cloudrail-test" {
  name           = "project-cloudrail-test"
  description    = "project-cloudrail-test"
  build_timeout  = "5"
  queued_timeout = "5"
  service_role   = aws_iam_role.codebuild.arn
  encryption_key = data.aws_kms_key.by_alias.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  cache {
    type  = "LOCAL"
    modes = ["LOCAL_DOCKER_LAYER_CACHE", "LOCAL_SOURCE_CACHE"]
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:1.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "SOME_KEY1"
      value = "SOME_VALUE1"
    }
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/foo/bar.git"
    git_clone_depth = 1
  }
}

```