---
title: "EFS without KMS"
group_id: "Terraform / AWS"
meta:
  name: "aws/efs_without_kms"
  id: "25d251f3-f348-4f95-845c-1090e41a615c"
  display_name: "EFS without KMS"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Encryption"
---
## Metadata

**Id:** `25d251f3-f348-4f95-845c-1090e41a615c`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system#kms_key_id)

### Description

This check ensures that Amazon Elastic File System (EFS) resources are configured with encryption enabled using a customer-managed KMS key specified via the `kms_key_id` attribute, rather than defaulting to AWS-managed keys. If only `encrypted = true` is set without specifying a `kms_key_id`, sensitive data stored in EFS will use default AWS-managed encryption keys, reducing control over key rotation and access management. Failure to use a customer-managed key increases the risk of unauthorized data access and may not meet stringent compliance requirements for sensitive workloads.

## Compliant Code Examples
```terraform
resource "aws_efs_file_system" "negative1" {
  creation_token = "my-product"
  encrypted = true
  kms_key_id = "1234abcd-12ab-34cd-56ef-1234567890ab"

  tags = {
    Name = "MyProduct"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_efs_file_system" "positive1" {
  creation_token = "my-product"
  encrypted = true

  tags = {
    Name = "MyProduct"
  }
}
```