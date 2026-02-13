---
title: "ECR repository is publicly accessible"
group_id: "Terraform / AWS"
meta:
  name: "aws/ecr_repository_is_publicly_accessible"
  id: "e86e26fc-489e-44f0-9bcd-97305e4ba69a"
  display_name: "ECR repository is publicly accessible"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `e86e26fc-489e-44f0-9bcd-97305e4ba69a`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy)

### Description

 Amazon ECR repository policies that use a wildcard `*` in the `Principal` field grant public access to your container images, potentially exposing sensitive data or proprietary code. When left unaddressed, this vulnerability allows unauthorized users to pull, and in some cases push, container images, compromising the integrity and confidentiality of your container deployments. To remediate this issue, always specify explicit IAM principals in your repository policies, such as `"Principal": { "AWS": "arn:aws:iam::account_number:root" }` instead of using `"Principal": "*"`.


## Compliant Code Examples
```terraform
resource "aws_ecr_repository" "negative1" {
  name = "bar"
}

resource "aws_ecr_repository_policy" "negative2" {
  repository = aws_ecr_repository.foo.name

  policy = <<EOF
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "new policy",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::##account_number##:root"
            },
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "ecr:ListImages",
                "ecr:DeleteRepository",
                "ecr:BatchDeleteImage",
                "ecr:SetRepositoryPolicy",
                "ecr:DeleteRepositoryPolicy"
            ]
        }
    ]
}
EOF
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_ecr_repository" "positive1" {
  name = "bar"
}

resource "aws_ecr_repository_policy" "positive2" {
  repository = aws_ecr_repository.foo.name

  policy = <<EOF
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "new policy",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "ecr:ListImages",
                "ecr:DeleteRepository",
                "ecr:BatchDeleteImage",
                "ecr:SetRepositoryPolicy",
                "ecr:DeleteRepositoryPolicy"
            ]
        }
    ]
}
EOF
}

```