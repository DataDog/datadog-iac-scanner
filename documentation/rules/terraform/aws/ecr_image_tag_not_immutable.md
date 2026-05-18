---
title: "ECR image tag not immutable"
group_id: "Terraform / AWS"
meta:
  name: "aws/ecr_image_tag_not_immutable"
  id: "terraform-aws-ecr-image-tag-not-immutable"
  display_name: "ECR image tag not immutable"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-aws-ecr-image-tag-not-immutable{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository)

### Description

To ensure the integrity of container images, Amazon Elastic Container Registry (ECR) repositories should have image tag immutability enabled by setting `image_tag_mutability` to `IMMUTABLE`. When image tags are set as mutable, existing image tags can be overwritten with new images, which may enable attackers or unauthorized users to replace trusted container images with malicious ones without changing the tag reference. This vulnerability can compromise the supply chain, leading to the deployment of untrusted or harmful workloads in production environments. Enforcing image tag immutability helps maintain a consistent and auditable history of deployed images, preventing accidental or intentional tampering of container tags.

## Compliant Code Examples
```terraform
resource "aws_ecr_repository" "foo" {
  name                 = "bar"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_ecr_repository" "foo2" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "foo3" {
  name                 = "bar"

  image_scanning_configuration {
    scan_on_push = true
  }
}

```