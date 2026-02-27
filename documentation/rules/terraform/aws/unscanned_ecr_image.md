---
title: "Unscanned ECR image"
group_id: "Terraform / AWS"
meta:
  name: "aws/unscanned_ecr_image"
  id: "9630336b-3fed-4096-8173-b9afdfe346a7"
  display_name: "Unscanned ECR image"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `9630336b-3fed-4096-8173-b9afdfe346a7`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#scan_on_push)

### Description

This check verifies whether Amazon Elastic Container Registry (ECR) repositories are configured to scan container images on push by setting the `scan_on_push` attribute to `true` in the `image_scanning_configuration` block. Without image scanning enabled, as in `image_scanning_configuration { scan_on_push = false }`, malicious or vulnerable software can be uploaded and distributed without detection, increasing the risk of security breaches. Enabling image scanning ensures that newly pushed images are automatically checked for vulnerabilities, helping to prevent the deployment of insecure containers.

## Compliant Code Examples
```terraform
resource "aws_ecr_repository" "negative1" {
  name                 = "bar"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_ecr_repository" "positive1" {
  name                 = "img_p_2"
  image_tag_mutability = "MUTABLE"
}

resource "aws_ecr_repository" "positive2" {
  name                 = "img_p_1"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}
```