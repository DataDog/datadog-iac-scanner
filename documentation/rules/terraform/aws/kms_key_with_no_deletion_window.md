---
title: "KMS key with no deletion window"
group_id: "Terraform / AWS"
meta:
  name: "aws/kms_key_with_no_deletion_window"
  id: "0b530315-0ea4-497f-b34c-4ff86268f59d"
  display_name: "KMS key with no deletion window"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `0b530315-0ea4-497f-b34c-4ff86268f59d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key)

### Description

 When creating an AWS KMS key using Terraform, the `deletion_window_in_days` attribute specifies the waiting period before a key is permanently deleted after a deletion request. If this attribute is not set or is configured with an excessively high value, such as `deletion_window_in_days = 31`, it can delay key deletion and increase exposure to accidental or malicious use if a compromised key remains active for longer than necessary. Setting a minimal but valid window, such as `deletion_window_in_days = 10`, reduces this risk by ensuring that keys are deleted more promptly after they are scheduled for removal.

```
resource "aws_kms_key" "negative1" {
  description             = "KMS key 1"

  is_enabled = true

  enable_key_rotation = true

  deletion_window_in_days = 10
}
```


## Compliant Code Examples
```terraform
resource "aws_kms_key" "negative1" {
  description             = "KMS key 1"
  
  is_enabled = true

  enable_key_rotation = true

  deletion_window_in_days = 10
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_kms_key" "positive1" {
  description             = "KMS key 1"
  
  is_enabled = true

  enable_key_rotation = true

}


resource "aws_kms_key" "positive2" {
  description             = "KMS key 1"
  
  is_enabled = true

  enable_key_rotation = true

  deletion_window_in_days = 31
}

```