---
title: "ECR repository without policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/ecr_repository_without_policy"
  id: "69e7c320-b65d-41bb-be02-d63ecc0bcc9d"
  display_name: "ECR repository without policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `69e7c320-b65d-41bb-be02-d63ecc0bcc9d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy)

### Description

Amazon Elastic Container Registry (ECR) repositories should have resource policies attached to them to enforce specific access controls. Without a repository policy, the repository may rely only on default AWS account permissions, which are not granular and may inadvertently allow unauthorized users or services to access, modify, or delete container images. This misconfiguration exposes the repository contents to security risks such as privilege escalation or data theft. To mitigate this, it is important to define an `aws_ecr_repository_policy` with the appropriate access permissions for each ECR repository.

## Compliant Code Examples
```terraform
resource "aws_ecr_repository" "foo" {
  name = "bar"
}

resource "aws_ecr_repository_policy" "foopolicy" {
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
## Non-Compliant Code Examples
```terraform
resource "aws_ecr_repository" "foo2" {
  name = "bar"
}


resource "aws_ecr_repository_policy" "foopolicy" {
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

```terraform
resource "aws_ecr_repository" "foo" {
  name = "bar"
}


```